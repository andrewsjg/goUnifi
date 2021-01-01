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

func TestDevices(t *testing.T) {
	client := createClient()
	ctx := context.Background()

	devices, err := client.getDevices(ctx)

	if err != nil {
		t.Errorf("getDevices returned an error: %s", err)
		return
	}

	for _, device := range devices.Data {
		//fmt.Println(string(device))
		usg := new(USG)
		if usg.unmarshal(device) {
			fmt.Println("Found a USG with model: " + usg.Model)
		}

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

	if siteDevices["USG"] != nil {
		// This feels a bit wrong. We know this will always be an interface to a USG so it can be cast without error. But it would be nicer if siteDevices was a list
		// of concrete objects of the correct type. Something like siteDevices.usg[0].Model. This can be done with a struct instead of a map, but then
		// it will have a static set of arrays for each device type which is equally ugly.
		
		fmt.Println("Found a USG with Model: " + siteDevices["USG"][0].(USG).Model)
	}

}
