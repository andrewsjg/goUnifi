package gounifi

import "strings"

// Utility functions used in the gounfi package

func findInSlice(slice []string, val string, caseSensitive bool) (int, bool) {

	for i, item := range slice {
		if !caseSensitive {
			item = strings.ToUpper(item)
			val = strings.ToUpper(val)
		}

		if item == val {
			return i, true
		}
	}
	return -1, false
}

// True is the model passed in is known to the client
func isKnownDeviceModel(model string) bool {
	_, isKnown := findInSlice(UbiquitiDevices, model, false)

	return isKnown
}
