package gounifi

import (
	"os"
	"testing"
)

func TestLogin(t *testing.T) {

	userName := os.Getenv("UNIFI_USER")
	password := os.Getenv("UNIFI_PASSWORD")

	t.Logf("Username: %s Password: %s", userName, password)

}
