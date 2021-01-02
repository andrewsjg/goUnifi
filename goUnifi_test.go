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
		usg := new(UGW3)
		if usg.Unmarshal(device) {
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

	fmt.Println("SD TEST")
	fmt.Println(siteDevices.UGW3)
}
