package gounifi

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func createClient() *Client {
	userName := os.Getenv("UNIFI_USER")
	password := os.Getenv("UNIFI_PASSWORD")

	return NewClient(userName, password, "default")

}

func TestHealth(t *testing.T) {

	client := createClient()

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

func TestSiteDevices(t *testing.T) {
	client := createClient()
	ctx := context.Background()

	siteDevices, err := client.GetSiteDevices(ctx)

	if err != nil {
		t.Errorf("siteDevices returned an error: %s", err)
		return
	}

	fmt.Printf("USG Count      : %d\n", len(siteDevices.UGW3))
	fmt.Printf("U7LR Count     : %d\n", len(siteDevices.U7LR))
	fmt.Printf("US8P60 Count   : %d\n", len(siteDevices.US8P60))
	fmt.Printf("USC8 Count     : %d\n", len(siteDevices.USC8))
	fmt.Printf("UNKNOWN Count  : %d\n", len(siteDevices.MODELUNKNOWN))
}
