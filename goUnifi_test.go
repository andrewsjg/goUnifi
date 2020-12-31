package gounifi

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func TestHealth(t *testing.T) {

	userName := os.Getenv("UNIFI_USER")
	password := os.Getenv("UNIFI_PASSWORD")

	client := NewClient(userName, password, "default")
	ctx := context.Background()

	siteHealth, err := client.GetSiteHealth(ctx)

	if err != nil {
		t.Errorf("SiteHealth returned an error: %s", err)
		return
	}

	for _, subsys := range siteHealth.Data {
		fmt.Printf("Subsystem: %s\tStatus: %s\n", subsys.Subsystem, subsys.Status)
	}

}
