package gounifi

import (
	"context"
	"fmt"
	"os"
	"testing"
)

func createClient() *Unifi {
	userName := os.Getenv("UNIFI_USER")
	password := os.Getenv("UNIFI_PASSWORD")

	return NewUnifi(userName, password, "default")

}

func TestHealth(t *testing.T) {

	unifi := createClient()

	ctx := context.Background()
	siteHealth, err := unifi.GetSiteHealth(ctx)

	if err != nil {
		t.Errorf("SiteHealth returned an error: %s", err)
		return
	}

	for _, subsys := range siteHealth.Data {
		fmt.Printf("Subsystem: %s\tStatus: %s\n", subsys.Subsystem, subsys.Status)
	}

}

func TestSiteDevices(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	siteDevices, err := unifi.GetSiteDevices(ctx)

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

func TestClients(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	clients, err := unifi.GetClients(ctx)

	if err != nil {
		t.Errorf("getClients returned an error: %s", err)
		return
	}

	fmt.Printf("Found %d active clients on the network\n", len(clients.Data))
}
