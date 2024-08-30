package solgo

import (
	"errors"
	"fmt"
	"github.com/goccy/go-json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	sources_pb "github.com/unpackdev/protos/dist/go/sources"
	"github.com/unpackdev/solgo/metadata"
	"github.com/unpackdev/solgo/utils"
)

var (
	ErrPathFound = errors.New("path found")

	// Global local sources path
	localSourcesPath string
)

// SetLocalSourcesPath sets the global local sources path.
// It returns an error if the provided path does not exist or cannot be accessed.
func SetLocalSourcesPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err // Return the error if the path does not exist or cannot be accessed
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", path)
	}
	localSourcesPath = path
	return nil
}

// GetLocalSourcesPath returns the global local sources path.
func GetLocalSourcesPath() string {
	return localSourcesPath
}

// SourceUnit represents a unit of source code in Solidity. It includes the name, path, and content of the source code.
type SourceUnit struct {
	Name    string `yaml:"name" json:"name"`
	Path    string `yaml:"path" json:"path"`
	Content string `yaml:"content" json:"content"`
}

// String returns a string representation of the SourceUnit.
func (s *SourceUnit) String() string {
	return fmt.Sprintf("SourceUnit{Name: %s, Path: %s, Content: %s}", s.Name, s.Path, s.Content)
}

// GetName returns the name of the SourceUnit.
func (s *SourceUnit) GetName() string {
	return s.Name
}

// GetPath returns the path of the SourceUnit.
func (s *SourceUnit) GetPath() string {
	return s.Path
}

// GetBasePath returns the base path of the SourceUnit.
func (s *SourceUnit) GetBasePath() string {
	return filepath.Base(s.Path)
}

// GetContent returns the content of the SourceUnit.
func (s *SourceUnit) GetContent() string {
	return s.Content
}

// ToProto converts a SourceUnit to a protocol buffer SourceUnit.
func (s *SourceUnit) ToProto() *sources_pb.SourceUnit {
	return &sources_pb.SourceUnit{
		Name:    s.Name,
		Path:    s.Path,
		Content: s.Content,
	}
}

// Sources represent a collection of SourceUnit.
// It includes a slice of SourceUnit and the name of the entry source unit.
type Sources struct {
	prepared             bool          `yaml:"-" json:"-"`
	SourceUnits          []*SourceUnit `yaml:"source_units" json:"source_units"`
	EntrySourceUnitName  string        `yaml:"entry_source_unit" json:"base_source_unit"`
	LocalSources         bool          `yaml:"local_sources" json:"local_sources"`
	MaskLocalSourcesPath bool          `yaml:"mask_local_sources_path" json:"mask_local_sources_path"`
	LocalSourcesPath     string        `yaml:"local_sources_path" json:"local_sources_path"`
}

// ArePrepared returns true if the Sources has been prepared.
func (s *Sources) ArePrepared() bool {
	return s.prepared
}

// GetUnits returns the SourceUnits in the Sources.
func (s *Sources) GetUnits() []*SourceUnit {
	return s.SourceUnits
}

// ToProto converts a Sources to a protocol buffer Sources.
func (s *Sources) ToProto() *sources_pb.Sources {
	var sourceUnits []*sources_pb.SourceUnit
	for _, sourceUnit := range s.SourceUnits {
		sourceUnits = append(sourceUnits, sourceUnit.ToProto())
	}

	return &sources_pb.Sources{
		EntrySourceUnitName:  s.EntrySourceUnitName,
		MaskLocalSourcesPath: s.MaskLocalSourcesPath,
		LocalSourcesPath:     s.LocalSourcesPath,
		SourceUnits:          sourceUnits,
	}
}

func NewSourcesFromPath(entrySourceUnitName, path string) (*Sources, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err // Return the error if the path does not exist or cannot be accessed
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", path)
	}

	var sourcesDir string

	if GetLocalSourcesPath() == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		sourcesDir = filepath.Clean(filepath.Join(dir, "sources"))
	} else {
		sourcesDir = GetLocalSourcesPath()
	}

	sources := &Sources{
		MaskLocalSourcesPath: true,
		LocalSourcesPath:     sourcesDir,
		LocalSources:         false,
		EntrySourceUnitName:  entrySourceUnitName,
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue // Skip directories
		}

		// Check if the file has a .sol extension
		if filepath.Ext(file.Name()) == ".sol" {
			filePath := filepath.Join(path, file.Name())

			content, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}

			sources.SourceUnits = append(sources.SourceUnits, &SourceUnit{
				Name:    strings.TrimSuffix(file.Name(), ".sol"),
				Path:    filePath,
				Content: string(content),
			})
		}
	}

	if err := sources.SortContracts(); err != nil {
		return nil, fmt.Errorf("failure while doing topological contract sorting: %s", err.Error())
	}

	return sources, nil
}

func NewUnsortedSourcesFromPath(entrySourceUnitName, path string) (*Sources, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err // Return the error if the path does not exist or cannot be accessed
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("path is not a directory: %s", path)
	}

	var sourcesDir string

	if GetLocalSourcesPath() == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		sourcesDir = filepath.Clean(filepath.Join(dir, "sources"))
	} else {
		sourcesDir = GetLocalSourcesPath()
	}

	sources := &Sources{
		MaskLocalSourcesPath: true,
		LocalSourcesPath:     sourcesDir,
		LocalSources:         false,
		EntrySourceUnitName:  entrySourceUnitName,
	}

	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() {
			continue // Skip directories
		}

		// Check if the file has a .sol extension
		if filepath.Ext(file.Name()) == ".sol" {
			filePath := filepath.Join(path, file.Name())

			content, err := os.ReadFile(filePath)
			if err != nil {
				return nil, err
			}

			sources.SourceUnits = append(sources.SourceUnits, &SourceUnit{
				Name:    strings.TrimSuffix(file.Name(), ".sol"),
				Path:    filePath,
				Content: string(content),
			})
		}
	}

	if err := sources.SortContracts(); err != nil {
		return nil, fmt.Errorf("failure while doing topological contract sorting: %s", err.Error())
	}

	return sources, nil
}

// NewSourcesFromMetadata creates a Sources from a metadata package ContractMetadata.
// This is a helper function that ensures easier integration when working with the metadata package.
func NewSourcesFromMetadata(md *metadata.ContractMetadata) *Sources {
	var sourcesDir string

	if GetLocalSourcesPath() == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		sourcesDir = filepath.Clean(filepath.Join(dir, "sources"))
	} else {
		sourcesDir = GetLocalSourcesPath()
	}

	sources := &Sources{
		MaskLocalSourcesPath: true,
		LocalSourcesPath:     sourcesDir,
		LocalSources:         false,
	}

	// First target is the target of the entry source unit...
	for _, name := range md.Settings.CompilationTarget {
		sources.EntrySourceUnitName = name
		break
	}

	// Getting name looks surreal and easy, probably won't work in all cases and is
	// too good to be true.
	for name, source := range md.Sources {
		sources.AppendSource(&SourceUnit{
			Name:    strings.TrimSuffix(filepath.Base(name), ".sol"),
			Path:    name,
			Content: source.Content,
		})
	}

	return sources
}

func NewSourcesFromProto(entryContractName string, sc *sources_pb.Sources) (*Sources, error) {
	var sourcesDir string

	if GetLocalSourcesPath() == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		sourcesDir = filepath.Clean(filepath.Join(dir, "sources"))
	} else {
		sourcesDir = GetLocalSourcesPath()
	}

	sources := &Sources{
		MaskLocalSourcesPath: true,
		LocalSourcesPath:     sourcesDir,
		EntrySourceUnitName:  entryContractName,
		LocalSources:         false,
	}

	for _, source := range sc.GetSourceUnits() {
		sources.AppendSource(&SourceUnit{
			Name:    strings.TrimSuffix(filepath.Base(source.Name), ".sol"),
			Path:    source.Name,
			Content: source.Content,
		})
	}

	if err := sources.SortContracts(); err != nil {
		return nil, fmt.Errorf("failure while doing topological contract sorting: %s", err.Error())
	}

	return sources, nil
}

// NewSourcesFromEtherScan creates a Sources from an EtherScan response.
// This is a helper function that ensures easier integration when working with the EtherScan provider.
// This includes BscScan, and other equivalent from the same family.
func NewSourcesFromEtherScan(entryContractName string, sc interface{}) (*Sources, error) {
	var sourcesDir string

	if GetLocalSourcesPath() == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		sourcesDir = filepath.Clean(filepath.Join(dir, "sources"))
	} else {
		sourcesDir = GetLocalSourcesPath()
	}

	sources := &Sources{
		MaskLocalSourcesPath: true,
		LocalSourcesPath:     sourcesDir,
		EntrySourceUnitName:  entryContractName,
		LocalSources:         false,
	}

	switch sourceCode := sc.(type) {
	case string:
		sources.AppendSource(&SourceUnit{
			Name:    entryContractName,
			Path:    fmt.Sprintf("%s.sol", entryContractName),
			Content: sourceCode,
		})
	case map[string]interface{}:
		// Create an instance of ContractMetadata
		var contractMetadata metadata.ContractMetadata

		// Marshal the map into JSON, then Unmarshal it into the ContractMetadata struct
		jsonBytes, err := json.Marshal(sourceCode)
		if err != nil {
			return nil, fmt.Errorf("error marshalling to json: %v", err)
		}

		if err := json.Unmarshal(jsonBytes, &contractMetadata); err != nil {
			return nil, fmt.Errorf("error unmarshalling to contract metadata: %v", err)
		}

		for name, source := range contractMetadata.Sources {
			sources.AppendSource(&SourceUnit{
				Name:    strings.TrimSuffix(filepath.Base(name), ".sol"),
				Path:    name,
				Content: source.Content,
			})
		}

	case metadata.ContractMetadata:
		for name, source := range sourceCode.Sources {
			sources.AppendSource(&SourceUnit{
				Name:    strings.TrimSuffix(filepath.Base(name), ".sol"),
				Path:    name,
				Content: source.Content,
			})
		}

		if err := sources.SortContracts(); err != nil {
			return nil, fmt.Errorf("failure while doing topological contract sorting: %s", err.Error())
		}

	default:
		return nil, fmt.Errorf("unknown source code type: %T", sourceCode)
	}

	return sources, nil
}

// NewUnsortedSourcesFromEtherScan creates a Sources from an EtherScan response.
// This is a helper function that ensures easier integration when working with the EtherScan provider.
// This includes BscScan, and other equivalent from the same family.
func NewUnsortedSourcesFromEtherScan(entryContractName string, sc interface{}) (*Sources, error) {
	var sourcesDir string

	if GetLocalSourcesPath() == "" {
		_, filename, _, _ := runtime.Caller(0)
		dir := filepath.Dir(filename)
		sourcesDir = filepath.Clean(filepath.Join(dir, "sources"))
	} else {
		sourcesDir = GetLocalSourcesPath()
	}

	sources := &Sources{
		MaskLocalSourcesPath: true,
		LocalSourcesPath:     sourcesDir,
		EntrySourceUnitName:  entryContractName,
		LocalSources:         false,
	}

	switch sourceCode := sc.(type) {
	case string:
		sources.AppendSource(&SourceUnit{
			Name:    entryContractName,
			Path:    fmt.Sprintf("%s.sol", entryContractName),
			Content: sourceCode,
		})
	case map[string]interface{}:
		// Create an instance of ContractMetadata
		var contractMetadata metadata.ContractMetadata

		// Marshal the map into JSON, then Unmarshal it into the ContractMetadata struct
		jsonBytes, err := json.Marshal(sourceCode)
		if err != nil {
			return nil, fmt.Errorf("error marshalling to json: %v", err)
		}

		if err := json.Unmarshal(jsonBytes, &contractMetadata); err != nil {
			return nil, fmt.Errorf("error unmarshalling to contract metadata: %v", err)
		}

		for name, source := range contractMetadata.Sources {
			sources.AppendSource(&SourceUnit{
				Name:    strings.TrimSuffix(filepath.Base(name), ".sol"),
				Path:    name,
				Content: source.Content,
			})
		}

	case metadata.ContractMetadata:
		for name, source := range sourceCode.Sources {
			sources.AppendSource(&SourceUnit{
				Name:    strings.TrimSuffix(filepath.Base(name), ".sol"),
				Path:    name,
				Content: source.Content,
			})
		}

	default:
		return nil, fmt.Errorf("unknown source code type: %T", sourceCode)
	}

	return sources, nil
}

// AppendSource appends a SourceUnit to the Sources.
// If a SourceUnit with the same name already exists, it replaces it unless the new SourceUnit has less content.
func (s *Sources) AppendSource(source *SourceUnit) {
	if s.SourceUnitPathExists(source.GetPath()) {
		unit := s.GetSourceUnitByPath(source.GetPath())

		if len(unit.Content) == len(source.Content) {
			return
		}

		if len(unit.Content) < len(source.Content) {
			s.ReplaceSource(unit, source)
			return
		}
	}

	s.SourceUnits = append(s.SourceUnits, source)
}

// ReplaceSource replaces an old SourceUnit with a new one.
// If the old SourceUnit is not found, nothing happens.
func (s *Sources) ReplaceSource(old *SourceUnit, newSource *SourceUnit) {
	for i, unit := range s.SourceUnits {
		if unit.GetName() == old.GetName() {
			s.SourceUnits[i] = newSource
		}
	}
}

// Validate checks the integrity of the Sources object.
// It ensures that:
// - There is at least one SourceUnit.
// - Each SourceUnit has a name and either a path or content.
// - If a SourceUnit has a path, the file at that path exists.
// - The entry source unit name is valid.
func (s *Sources) Validate() error {
	// Ensure there is at least one SourceUnit.
	if len(s.SourceUnits) == 0 {
		return errors.New("no source units found")
	}

	// Validate each SourceUnit.
	for _, sourceUnit := range s.SourceUnits {
		if sourceUnit.Name == "" {
			return errors.New("source unit must have a name")
		}
		if sourceUnit.Path == "" && sourceUnit.Content == "" {
			return fmt.Errorf("source unit %s must have either path or content", sourceUnit.Name)
		}
	}

	// Validate the entry source unit name.
	if s.EntrySourceUnitName != "" {
		entrySourceUnit := s.GetSourceUnitByName(s.EntrySourceUnitName)
		if entrySourceUnit == nil {
			// It may be that the entry source unit is not found because it's not
			// in one file provided back to us. In that case, we should check if
			// specific file contains `contract {entrySourceUnitName}`.
			found := false
			contractRegex := regexp.MustCompile(fmt.Sprintf(`\bcontract\s+%s\b`, regexp.QuoteMeta(s.EntrySourceUnitName)))
			libraryRegex := regexp.MustCompile(fmt.Sprintf(`\blibrary\s+%s\b`, regexp.QuoteMeta(s.EntrySourceUnitName)))

			for _, sourceUnit := range s.SourceUnits {
				if contractRegex.MatchString(sourceUnit.Content) || libraryRegex.MatchString(sourceUnit.Content) {
					found = true
					break
				}
			}

			if !found {
				return fmt.Errorf("entry source unit %s not found", s.EntrySourceUnitName)
			}
		}
	}

	return nil
}

// Prepare validates and prepares the Sources. It checks if each SourceUnit has either a path or content and a name.
// If a SourceUnit has a path but no content, it reads the content from the file at the path.
func (s *Sources) Prepare() error {

	// We should verify that path can be discovered if local sources path is
	// provided.
	if s.LocalSourcesPath != "" {
		if _, err := os.Stat(s.LocalSourcesPath); err != nil {
			return fmt.Errorf("local sources path %s does not exist", s.LocalSourcesPath)
		}
	} else {
		s.LocalSourcesPath = "./sources/"
	}

	for _, sourceUnit := range s.SourceUnits {
		if sourceUnit.Path == "" && sourceUnit.Content == "" {
			return fmt.Errorf("source unit must have either path or content")
		}

		if sourceUnit.Name == "" {
			return fmt.Errorf("source unit must have a name")
		}

		if sourceUnit.Path != "" && sourceUnit.Content == "" {
			content, err := os.ReadFile(sourceUnit.Path)
			if err != nil {
				return err
			}
			sourceUnit.Content = string(content)
		}

		// Extract import statements as perhaps some of them can be found in
		// local sources path and need to be prepended to the sources.
		importUnits, err := s.handleImports(sourceUnit)
		if err != nil {
			return err
		}

		s.SourceUnits = append(s.SourceUnits, importUnits...)
	}

	if err := s.SortContracts(); err != nil {
		return fmt.Errorf("failure while doing topological contract sorting: %s", err.Error())
	}

	// Mark sources as prepared for future use.
	s.prepared = true

	if err := s.Validate(); err != nil {
		return err
	}

	return nil
}

// GetCombinedSource combines the content of all SourceUnits in the Sources into a single string, separated by two newlines.
func (s *Sources) GetCombinedSource() string {
	var builder strings.Builder
	for i, sourceUnit := range s.SourceUnits {
		if i > 0 {
			builder.WriteString("\n\n")
		}
		builder.WriteString(sourceUnit.Content)
	}
	return builder.String()
}

// GetSourceUnitByName returns the SourceUnit with the given name from the Sources. If no such SourceUnit exists, it returns nil.
func (s *Sources) GetSourceUnitByName(name string) *SourceUnit {
	for _, sourceUnit := range s.SourceUnits {
		if sourceUnit.Name == name {
			return sourceUnit
		}
	}
	return nil
}

// GetSourceUnitByNameAndSize returns the SourceUnit with the given name and size from the Sources. If no such SourceUnit exists, it returns nil.
func (s *Sources) GetSourceUnitByNameAndSize(name string, size int) *SourceUnit {
	for _, sourceUnit := range s.SourceUnits {
		if sourceUnit.Name == name && len(sourceUnit.Content) == size {
			return sourceUnit
		}
	}
	return nil
}

// GetSourceUnitByPath returns the SourceUnit with the given path from the Sources. If no such SourceUnit exists, it returns nil.
func (s *Sources) GetSourceUnitByPath(path string) *SourceUnit {
	for _, sourceUnit := range s.SourceUnits {
		if sourceUnit.Path == path {
			return sourceUnit
		}
	}
	return nil
}

// HasUnits returns true if the Sources has at least one SourceUnit.
func (s *Sources) HasUnits() bool {
	return len(s.SourceUnits) > 0
}

// GetLocalSource attempts to find a local source file that matches the given partial path.
// It searches relative to the provided path and returns a SourceUnit representing the found source.
// If no matching source is found, it returns nil.
//
// The function replaces any instance of "@openzeppelin" in the partial path with the actual path to the openzeppelin-contracts repository.
// It then walks the file tree starting from "./sources/", checking each file against the new path.
//
// If the new path contains "../", it removes this and looks for the file in the parent directory.
// If a match is found, it creates a new SourceUnit with the name and path of the file, and returns it.
//
// If no "../" is present in the new path, it simply creates a new SourceUnit with the name and path.
//
// After a SourceUnit is created, the function checks if the file at the path exists.
// If it does, it reads the file content and assigns it to the SourceUnit's Content field.
// If the file does not exist, it returns an error.
//
// If the walk function encounters an error other than ErrPathFound, it returns the error.
// If the source is still nil after the walk, it returns nil.
func (s *Sources) GetLocalSource(partialPath string, relativeTo string) (*SourceUnit, error) {
	// Replace @openzeppelin with the actual path to the openzeppelin-contracts repository
	partialPath = replaceOpenZeppelin(partialPath)
	relativeTo = replaceOpenZeppelin(relativeTo)
	var source *SourceUnit
	errWalk := filepath.Walk(s.LocalSourcesPath, func(partialWalkPath string, info os.FileInfo, err error) error {
		if info == nil || info.IsDir() {
			return nil
		}

		relativeToDir := filepath.Dir(relativeTo)
		newPath := filepath.Join(relativeToDir, partialPath)

		// If file contains ../, remove it and look for the file in the parent directory
		if strings.Contains(newPath, "../") {
			newPath = strings.TrimSpace(strings.Replace(newPath, "../", "", -1))
			if strings.Contains(partialWalkPath, newPath) {
				sourceName := strings.TrimSuffix(filepath.Base(newPath), ".sol")
				if !s.SourceUnitExists(sourceName) {
					source = &SourceUnit{
						Name: sourceName,
						Path: partialWalkPath,
					}
				}
				return ErrPathFound
			}
		}

		sourceName := strings.TrimSuffix(filepath.Base(newPath), ".sol")
		if !s.SourceUnitExists(sourceName) {
			if strings.Contains(partialWalkPath, newPath) {
				source = &SourceUnit{
					Name: sourceName,
					Path: partialWalkPath,
				}
			}
		}

		return nil
	})

	if errWalk != nil && errWalk != ErrPathFound {
		return nil, errWalk
	}

	if source == nil {
		return nil, nil
	}

	if _, err := os.Stat(source.Path); os.IsNotExist(err) {
		return nil, err
	}

	content, err := os.ReadFile(source.Path)
	if err != nil {
		return nil, err
	}

	source.Content = string(content)
	return source, nil
}

// SourceUnitExists returns true if a SourceUnit with the given name exists in the Sources.
func (s *Sources) SourceUnitExists(name string) bool {
	return s.SourceUnitExistsIn(name, s.SourceUnits)
}

// SourceUnitExists returns true if a SourceUnit with the given name exists in the Sources.
func (s *Sources) SourceUnitPathExists(name string) bool {
	return s.SourceUnitPathExistsIn(name, s.SourceUnits)
}

// SourceUnitExistsIn returns true if a SourceUnit with the given name exists in the given slice of SourceUnits.
func (s *Sources) SourceUnitExistsIn(name string, units []*SourceUnit) bool {
	for _, sourceUnit := range units {
		if sourceUnit.Name == name {
			return true
		}
	}
	return false
}

// SourceUnitExistsIn returns true if a SourceUnit with the given name exists in the given slice of SourceUnits.
func (s *Sources) SourceUnitPathExistsIn(name string, units []*SourceUnit) bool {
	for _, sourceUnit := range units {
		if sourceUnit.Path == name {
			return true
		}
	}
	return false
}

// WriteToDir writes each SourceUnit's content to a file in the specified directory.
func (s *Sources) WriteToDir(path string) error {
	// Ensure the specified directory exists or create it
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(path, 0700); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", path, err)
		}
	}

	// Write each SourceUnit's content to a file in the specified directory
	for _, sourceUnit := range s.SourceUnits {
		// WARN: Left it here as a future - BIG NO NO - import paths will be skewed and won't able to parse
		// properly + we won't be able to share sources with everyone else as-they-are...
		// content := utils.SimplifyImportPaths(sourceUnit.Content)

		filePath := filepath.Join(path, sourceUnit.Name+".sol")

		if err := utils.WriteToFile(filePath, []byte(sourceUnit.Content)); err != nil {
			return fmt.Errorf("failed to write source unit %s to file: %v", sourceUnit.Name, err)
		}
	}

	return nil
}

// TruncateDir removes all files and subdirectories within the specified directory.
func (s *Sources) TruncateDir(path string) error {
	// Open the directory
	dir, err := os.Open(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("failed to open directory %s: %v", path, err)
	}
	defer dir.Close()

	// Read the directory entries
	entries, err := dir.Readdir(-1)
	if err != nil {
		return fmt.Errorf("failed to read directory entries for %s: %v", path, err)
	}

	// Iterate over each entry and remove it
	for _, entry := range entries {
		entryPath := filepath.Join(path, entry.Name())
		if entry.IsDir() {
			// If the entry is a directory, recursively remove it
			err := os.RemoveAll(entryPath)
			if err != nil {
				return fmt.Errorf("failed to remove directory %s: %v", entryPath, err)
			}
		} else {
			// If the entry is a file, remove it
			err := os.Remove(entryPath)
			if err != nil {
				return fmt.Errorf("failed to remove file %s: %v", entryPath, err)
			}
		}
	}

	return nil
}

// GetSolidityVersion extracts the highest Solidity version from all source units.
func (s *Sources) GetSolidityVersion() (string, error) {
	// Use a regular expression to match the pragma solidity statement
	// This regex will match versions like ^0.x.x and extract only 0.x.x
	re := regexp.MustCompile(`pragma solidity\s*\^?(\d+\.\d+\.\d+);`)

	var highestVersion string

	for _, sourceUnit := range s.SourceUnits {
		match := re.FindStringSubmatch(sourceUnit.Content)

		if len(match) >= 2 {
			currentVersion := match[1]
			if compareVersions(currentVersion, highestVersion) > 0 {
				highestVersion = currentVersion
			}
		}
	}

	if highestVersion == "" {
		return "", fmt.Errorf("no solidity version found in any source unit")
	}

	return highestVersion, nil
}

// handleImports extracts import statements from the source unit and adds them to the sources.
func (s *Sources) handleImports(sourceUnit *SourceUnit) ([]*SourceUnit, error) {
	imports := extractImports(sourceUnit.Content)
	var sourceUnits []*SourceUnit

	if !s.LocalSources {
		return sourceUnits, nil
	}

	for _, imp := range imports {
		baseName := filepath.Base(imp)

		if !s.SourceUnitExists(baseName) {
			source, err := s.GetLocalSource(imp, sourceUnit.Path)
			if err != nil {
				return nil, err
			}

			// Source may not be found and no errors and that's ok, however, we don't want to append
			// nil source to the sources.
			if source == nil {
				continue
			}

			if !s.SourceUnitExistsIn(source.Name, sourceUnits) {
				sourceUnits = append(sourceUnits, source)
			}

			subUnits, err := s.handleImports(source)
			if err != nil {
				return nil, err
			}

			for _, subUnit := range subUnits {
				if !s.SourceUnitExistsIn(subUnit.Name, sourceUnits) {
					sourceUnits = append(sourceUnits, subUnit)
				}
			}
		}
	}

	return sourceUnits, nil
}

// extractImports extracts import statements from the source unit.
func extractImports(content string) []string {
	re := regexp.MustCompile(`import "(.*?)";`)
	matches := re.FindAllStringSubmatch(content, -1)

	imports := make([]string, 0)
	for _, match := range matches {
		imports = append(imports, match[1])
	}

	return imports
}

// replaceOpenZeppelin replaces the @openzeppelin path with the actual path to the openzeppelin-contracts repository.
func replaceOpenZeppelin(path string) string {
	return strings.Replace(path, "@openzeppelin", filepath.Join("./sources/", "openzeppelin"), 1)
}

// Node represents a unit of source code in Solidity with its dependencies.
type Node struct {
	Name         string
	Size         int
	Content      string
	Dependencies []string
}

// SortContracts sorts the SourceUnits based on their dependencies.
func (s *Sources) SortContracts() error {
	var nodes []Node
	for _, sourceUnit := range s.SourceUnits {
		imports := extractImports(sourceUnit.Content)
		var dependencies []string
		for _, imp := range imports {
			baseName := filepath.Base(imp)
			dependencies = append(dependencies, strings.TrimSuffix(baseName, ".sol"))
		}
		nodes = append(nodes, Node{
			Name:         sourceUnit.Name,
			Size:         len(sourceUnit.Content),
			Content:      sourceUnit.Content,
			Dependencies: dependencies,
		})
	}

	// Use a combination of Name and Content for uniqueness
	uniqueKey := func(node Node) string {
		return node.Name + "_" + strconv.Itoa(len(node.Content))
	}

	uniqueNodesMap := make(map[string]bool)
	var uniqueNodesSlice []Node

	for _, node := range nodes {
		key := uniqueKey(node)
		if _, exists := uniqueNodesMap[key]; !exists {
			uniqueNodesMap[key] = true
			uniqueNodesSlice = append(uniqueNodesSlice, node)
		}
	}

	originalOrderMap := make(map[string]int)
	for i, sourceUnit := range s.SourceUnits {
		originalOrderMap[sourceUnit.Name] = i
	}

	sortedNodes, err := topologicalSort(nodes, originalOrderMap)
	if err != nil {
		return err
	}

	var sortedSourceUnits []*SourceUnit
	for _, node := range sortedNodes {
		if sourceUnit := s.GetSourceUnitByNameAndSize(node.Name, node.Size); sourceUnit != nil {
			sortedSourceUnits = append(sortedSourceUnits, sourceUnit)
		}
	}

	s.SourceUnits = sortedSourceUnits
	return nil
}

// topologicalSort performs a topological sort on the given nodes based on their dependencies.
// It returns a slice of nodes sorted in a way that for every directed edge U -> V,
// node U comes before V in the ordering. If a cycle is detected, the function will
// continue without error, but the result may not be a valid topological order.
func topologicalSort(nodes []Node, originalOrder map[string]int) ([]Node, error) {
	var sorted []Node
	visited := make(map[string]bool)
	onStack := make(map[string]bool) // To detect cycles

	// Helper function to generate a unique key for each node
	uniqueKey := func(node Node) string {
		return node.Name + "_" + strconv.Itoa(node.Size)
	}

	var visit func(node Node) error
	visit = func(node Node) error {
		nodeKey := uniqueKey(node)
		if onStack[nodeKey] {
			// Detected a cycle, but we'll continue without error
			return nil
		}
		if visited[nodeKey] {
			return nil
		}
		visited[nodeKey] = true
		onStack[nodeKey] = true

		// Sort dependencies for consistent order
		sort.SliceStable(node.Dependencies, func(i, j int) bool {
			depIKey := node.Dependencies[i]
			depJKey := node.Dependencies[j]
			return originalOrder[depIKey] < originalOrder[depJKey]
		})

		for _, depName := range node.Dependencies {
			for _, depNode := range nodes {
				if depNode.Name == depName {
					if err := visit(depNode); err != nil {
						return err
					}
				}
			}
		}

		sorted = append(sorted, node)
		onStack[nodeKey] = false
		return nil
	}

	originalOrderMap := make(map[string]int)
	for i, node := range nodes {
		originalOrderMap[node.Name] = i
	}

	for _, node := range nodes {
		if !visited[uniqueKey(node)] {
			if err := visit(node); err != nil {
				return nil, err
			}
		}
	}

	return sorted, nil
}

// compareVersions compares two version strings and returns:
// -1 if v1 < v2
//
//	0 if v1 == v2
//	1 if v1 > v2
func compareVersions(v1, v2 string) int {
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	// This is the first run to comparation and therefore, we should ensure it's setting it
	// to the highest version.
	if len(v2Parts) < 3 {
		return 1
	}

	for i := 0; i < 3; i++ {
		v1Int, _ := strconv.Atoi(v1Parts[i])
		v2Int, _ := strconv.Atoi(v2Parts[i])
		if v1Int < v2Int {
			return -1
		} else if v1Int > v2Int {
			return 1
		}
	}
	return 0
}
