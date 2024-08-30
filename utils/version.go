package utils

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
)

// SemanticVersion represents a semantic version, following the Major.Minor.Patch
// format. Optionally, a version can include a commit revision as a metadata string
// appended after a plus sign (+).
type SemanticVersion struct {
	Major  int    `json:"major"`              // Major version, incremented for incompatible API changes.
	Minor  int    `json:"minor"`              // Minor version, incremented for backwards-compatible enhancements.
	Patch  int    `json:"patch"`              // Patch version, incremented for backwards-compatible bug fixes.
	Commit string `json:"revision,omitempty"` // Optional commit revision for tracking specific builds.
}

// Bytes serializes the SemanticVersion into a byte slice.
func (v SemanticVersion) Bytes() []byte {
	buf := new(bytes.Buffer)

	// Write Major, Minor, Patch as int32
	binary.Write(buf, binary.BigEndian, int32(v.Major))
	binary.Write(buf, binary.BigEndian, int32(v.Minor))
	binary.Write(buf, binary.BigEndian, int32(v.Patch))

	// Write Commit with length prefix
	if v.Commit != "" {
		commitBytes := []byte(v.Commit)
		binary.Write(buf, binary.BigEndian, uint32(len(commitBytes)))
		buf.Write(commitBytes)
	} else {
		binary.Write(buf, binary.BigEndian, uint32(0)) // No commit
	}

	return buf.Bytes()
}

// String returns the string representation of the SemanticVersion, excluding the
// commit revision. It adheres to the "Major.Minor.Patch" format.
func (v SemanticVersion) String() string {
	if v.Commit != "" {
		return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch) + "+" + v.Commit
	}

	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// String returns the string representation of the SemanticVersion, excluding the
// commit revision. It adheres to the "Major.Minor.Patch" format.
func (v SemanticVersion) StringVersion() string {
	return strconv.Itoa(v.Major) + "." + strconv.Itoa(v.Minor) + "." + strconv.Itoa(v.Patch)
}

// ParseSemanticVersion parses a version string into a SemanticVersion struct.
// The function supports version strings in the "Major.Minor.Patch" format, with
// an optional commit revision appended after a plus sign (+). The 'v' prefix
// in version strings is also supported and ignored during parsing.
func ParseSemanticVersion(version string) SemanticVersion {
	versions := strings.Split(version, "+")
	var commit string
	if len(versions) > 1 {
		version = versions[0]
		commit = versions[1]
	}

	version = strings.Replace(version, "v", "", 1)
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return SemanticVersion{}
	}

	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patch, _ := strconv.Atoi(parts[2])
	return SemanticVersion{
		Major:  major,
		Minor:  minor,
		Patch:  patch,
		Commit: commit,
	}
}

func ParseSemanticVersionFromBytes(data []byte) (SemanticVersion, error) {
	buf := bytes.NewReader(data)
	v := SemanticVersion{}

	var major, minor, patch int32
	var commitLen uint32

	// Read Major, Minor, Patch
	if err := binary.Read(buf, binary.BigEndian, &major); err != nil {
		return v, err
	}

	if err := binary.Read(buf, binary.BigEndian, &minor); err != nil {
		return v, err
	}

	if err := binary.Read(buf, binary.BigEndian, &patch); err != nil {
		return v, err
	}

	v.Major = int(major)
	v.Minor = int(minor)
	v.Patch = int(patch)

	// Read Commit length
	if err := binary.Read(buf, binary.BigEndian, &commitLen); err != nil {
		return v, err
	}

	if commitLen > 0 {
		commitBytes := make([]byte, commitLen)
		if _, err := buf.Read(commitBytes); err != nil {
			return v, err
		}
		v.Commit = string(commitBytes)
	} else {
		v.Commit = ""
	}

	return v, nil
}

// IsSemanticVersionGreaterOrEqualTo checks if the version represented by a string
// is greater than or equal to the provided SemanticVersion. The comparison takes
// into account the Major, Minor, and Patch components of the semantic version.
func IsSemanticVersionGreaterOrEqualTo(versionStr string, version SemanticVersion) bool {
	parsedVersion := ParseSemanticVersion(versionStr)

	if parsedVersion.Major == version.Major && parsedVersion.Minor == version.Minor && parsedVersion.Patch >= version.Patch {
		return true
	}

	if parsedVersion.Major == version.Major && parsedVersion.Minor > version.Minor {
		return true
	}

	if parsedVersion.Major > version.Major && parsedVersion.Minor == version.Minor && parsedVersion.Patch == version.Patch {
		return true
	}

	return false
}

// IsSemanticVersionLowerOrEqualTo checks if the version represented by a string
// is lower than or equal to the provided SemanticVersion. The comparison considers
// the Major, Minor, and Patch components of the semantic version.
func IsSemanticVersionLowerOrEqualTo(versionStr string, version SemanticVersion) bool {
	parsedVersion := ParseSemanticVersion(versionStr)
	if parsedVersion.Major == version.Major && parsedVersion.Minor == version.Minor && parsedVersion.Patch < version.Patch {
		return true
	}

	if parsedVersion.Major == version.Major && parsedVersion.Minor < version.Minor {
		return true
	}

	if parsedVersion.Major < version.Major && parsedVersion.Minor == version.Minor && parsedVersion.Patch == version.Patch {
		return true
	}

	return false
}
