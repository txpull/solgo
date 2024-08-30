package simulator

// ToAnvilProvider attempts to cast a generic Provider interface to a specific *AnvilProvider type.
// This is useful when you need to work with the specific methods and properties of AnvilProvider
// that are not part of the generic Provider interface.
func ToAnvilProvider(provider Provider) (*AnvilProvider, bool) {
	if provider == nil {
		return nil, false
	}

	anvilProvider, ok := provider.(*AnvilProvider)
	if !ok {
		return nil, false
	}

	return anvilProvider, true
}
