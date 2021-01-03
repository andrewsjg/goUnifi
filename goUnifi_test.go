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

func TestActiveClients(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	clients, err := unifi.GetActiveClients(ctx)

	if err != nil {
		t.Errorf("getClients returned an error: %s", err)
		return
	}

	fmt.Printf("%d active clients on the network\n", len(clients.Clients))
}

func TestKnownClients(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	knownClients, err := unifi.GetKnownClients(ctx)

	if err != nil {
		t.Errorf("GetKnownClients returned an error: %s", err)
		return
	}

	fmt.Printf("%d clients known to the network\n", len(knownClients.Clients))

}

func TestSiteSettings(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	siteSettings, err := unifi.GetSiteSettings(ctx)

	if err != nil {
		t.Errorf("SiteSettings returned an error: %s", err)
		return
	}
	fmt.Println("Available Settings:")
	for _, setting := range siteSettings.Data {
		fmt.Println(setting.Key)
	}
}

func TestGetRoutes(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	routing, err := unifi.GetRoutes(ctx)

	if err != nil {
		t.Errorf("Routing returned an error: %s", err)
		return
	}

	fmt.Println("Routes Defined for:")
	for _, route := range routing.Data {
		fmt.Println(route.Pfx)
	}
}

func TestGetFirewallRules(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	firewallRules, err := unifi.GetFirewallRules(ctx)

	if err != nil {
		t.Errorf("FirewallRules returned an error: %s", err)
		return
	}

	fmt.Println("User Defined Firewall rules for:")
	for _, fwRule := range firewallRules.Data {
		fmt.Println(fwRule.Name)
	}
}

func TestGetFirewallGroups(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	firewallGroups, err := unifi.GetFirewallGroups(ctx)

	if err != nil {
		t.Errorf("FirewallRules returned an error: %s", err)
		return
	}

	fmt.Println("User Defined Firewall Groups for:")
	for _, fwRule := range firewallGroups.Data {
		fmt.Println(fwRule.Name)
	}
}
