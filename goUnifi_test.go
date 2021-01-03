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
		t.Errorf("FirewallGroups returned an error: %s", err)
		return
	}

	fmt.Println("User Defined Firewall Groups for:")
	for _, fwRule := range firewallGroups.Data {
		fmt.Println(fwRule.Name)
	}
}

func TestGetWLANConf(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	wlanConf, err := unifi.GetWLANConf(ctx)

	if err != nil {
		t.Errorf("WLANConfs returned an error: %s", err)
		return
	}

	fmt.Println("Wireless LANS:")
	for _, wlan := range wlanConf.Data {
		fmt.Println(wlan.Name)
	}
}

func TestRogueAPs(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	rogueAPs, err := unifi.GetRogueAPs(ctx)

	if err != nil {
		t.Errorf("RogueAPs returned an error: %s", err)
		return
	}

	fmt.Printf("%d Foriegn WIFI Networks Seen\n", len(rogueAPs.Data))
}

func TestPortProfiles(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	portProfiles, err := unifi.GetPortProfiles(ctx)

	if err != nil {
		t.Errorf("PortProfiles returned an error: %s", err)
		return
	}

	fmt.Println("Port Profiles:")
	for _, portProfile := range portProfiles.Data {
		fmt.Println(portProfile.Name)
	}
}

func TestRadiusProfiles(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	radiusProfiles, err := unifi.GetRadiusProfiles(ctx)

	if err != nil {
		t.Errorf("RadiusProfiles returned an error: %s", err)
		return
	}

	fmt.Println("Radius Profiles:")
	for _, radiusProfile := range radiusProfiles.Data {
		fmt.Println(radiusProfile.Name)
	}
}

func TestRadiusAccounts(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	radiusAccounts, err := unifi.GetRadiusAccounts(ctx)

	if err != nil {
		t.Errorf("RadiusAccounts returned an error: %s", err)
		return
	}

	fmt.Println("Radius Accounts:")
	for _, radiusAccount := range radiusAccounts.Data {
		fmt.Println(radiusAccount.Name)
	}
}

func TestPortForwardRules(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	portForwardRules, err := unifi.GetPortForwardRules(ctx)

	if err != nil {
		t.Errorf("PortForwardRules returned an error: %s", err)
		return
	}

	fmt.Println("Port Forwarding Rules:")
	for _, portForwardRule := range portForwardRules.Data {
		t.Log(portForwardRule.Name)
	}
}

func TestRFChannels(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	rfChannels, err := unifi.GetRFChannels(ctx)

	if err != nil {
		t.Errorf("RFChannels returned an error: %s", err)
		return
	}

	if len(rfChannels.Data) >= 1 {
		t.Logf("Configured Country is %s\n", rfChannels.Data[0].Name)
	}
}

func TestCountryCodes(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	countryCodes, err := unifi.GetCountryCodes(ctx)

	if err != nil {
		t.Errorf("CountryCodes returned an error: %s", err)
		return
	}

	t.Logf("%d country codes found\n", len(countryCodes.Data))
}

func TestLoggedInUser(t *testing.T) {
	unifi := createClient()
	ctx := context.Background()

	loggedinUser, err := unifi.GetUser(ctx)

	if err != nil {
		t.Errorf("GetUser returned an error: %s", err)
		return
	}

	if len(loggedinUser.Data) >= 1 {
		t.Logf("%s is the current user\n", loggedinUser.Data[0].Name)
	}
}
