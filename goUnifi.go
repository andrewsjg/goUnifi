package gounifi

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	baseURL = "https://unifi:8443/api"
)

// Unifi - API Client
type Unifi struct {
	BaseURL    string
	userName   string
	password   string
	site       string
	HTTPClient *http.Client
}

// NewUnifi - Create a new API Client
func NewUnifi(username string, password string, site string) *Unifi {

	// Not really using the cookie jar here. Leaving in place because I might revisit
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil { // TODO: error handling
	}

	return &Unifi{
		BaseURL:    baseURL,
		userName:   username,
		password:   password,
		site:       site,
		HTTPClient: &http.Client{Timeout: time.Minute, Jar: jar},
	}

}

//GetSiteHealth Calls /api/s/<site>/stat/health
func (c *Unifi) GetSiteHealth(ctx context.Context) (*SiteHealth, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/stat/health", c.BaseURL, c.site), nil)

	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	result := SiteHealth{}

	if err := c.sendRequest(req, &result); err != nil {
		log.Println("ERROR: " + err.Error())
		return nil, err
	}

	return &result, nil
}

//GetDevices Calls /api/s/<site>/stat/device
func (c *Unifi) getDevices(ctx context.Context) (*Devices, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/stat/device", c.BaseURL, c.site), nil)

	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	result := Devices{}

	if err := c.sendRequest(req, &result); err != nil {
		log.Println("ERROR: " + err.Error())
		return nil, err
	}

	return &result, nil
}

//GetSiteDevices - Returns a map of all the devices in a site
func (c *Unifi) GetSiteDevices(ctx context.Context) (SiteDevices, error) {
	var siteDevices SiteDevices = SiteDevices{}

	devices, err := c.getDevices(ctx)

	if err != nil {
		return siteDevices, err
	}

	for _, deviceData := range devices.Data {
		siteDevices.Update(deviceData)
	}

	return siteDevices, nil
}

//GetActiveClients - Retrieves information about all active clients on the network
func (c *Unifi) GetActiveClients(ctx context.Context) (ActiveClients, error) {
	clients := ActiveClients{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/stat/sta", c.BaseURL, c.site), nil)

	if err != nil {
		return clients, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &clients); err != nil {
		log.Println("ERROR: " + err.Error())
		return clients, err
	}

	return clients, nil
}

//GetKnownClients - Retrieves information about all known clients seen on the network
func (c *Unifi) GetKnownClients(ctx context.Context) (KnownClients, error) {
	knownClients := KnownClients{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/user", c.BaseURL, c.site), nil)

	if err != nil {
		return knownClients, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &knownClients); err != nil {
		log.Println("ERROR: " + err.Error())
		return knownClients, err
	}

	return knownClients, nil
}

//GetSiteSettings - Retrieves Detailed Site Settings
func (c *Unifi) GetSiteSettings(ctx context.Context) (SiteSettings, error) {
	siteSettings := SiteSettings{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/setting", c.BaseURL, c.site), nil)

	if err != nil {
		return siteSettings, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &siteSettings); err != nil {
		log.Println("ERROR: " + err.Error())
		return siteSettings, err
	}

	return siteSettings, nil
}

//GetRoutes - Retrieves Routing Details
func (c *Unifi) GetRoutes(ctx context.Context) (Routing, error) {
	routing := Routing{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/stat/routing", c.BaseURL, c.site), nil)

	if err != nil {
		return routing, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &routing); err != nil {
		log.Println("ERROR: " + err.Error())
		return routing, err
	}

	return routing, nil
}

//GetFirewallRules - Retrieves user defined firewall rules
func (c *Unifi) GetFirewallRules(ctx context.Context) (FirewallRules, error) {
	firewallRules := FirewallRules{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/firewallrule", c.BaseURL, c.site), nil)

	if err != nil {
		return firewallRules, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &firewallRules); err != nil {
		log.Println("ERROR: " + err.Error())
		return firewallRules, err
	}

	return firewallRules, nil
}

//GetFirewallGroups - Retrieves user defined firewall groups
func (c *Unifi) GetFirewallGroups(ctx context.Context) (FirewallGroups, error) {
	firewallGroups := FirewallGroups{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/firewallgroup", c.BaseURL, c.site), nil)

	if err != nil {
		return firewallGroups, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &firewallGroups); err != nil {
		log.Println("ERROR: " + err.Error())
		return firewallGroups, err
	}

	return firewallGroups, nil
}

//GetWLANConf - Retrieves user defined firewall groups
func (c *Unifi) GetWLANConf(ctx context.Context) (WLANConf, error) {
	wlanConf := WLANConf{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/wlanconf", c.BaseURL, c.site), nil)

	if err != nil {
		return wlanConf, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &wlanConf); err != nil {
		log.Println("ERROR: " + err.Error())
		return wlanConf, err
	}

	return wlanConf, nil
}

//GetRogueAPs - Retrieves a list of Wireless AP's not part of the network that have been seen
func (c *Unifi) GetRogueAPs(ctx context.Context) (RogueAPs, error) {
	rogueAPs := RogueAPs{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/stat/rogueap", c.BaseURL, c.site), nil)

	if err != nil {
		return rogueAPs, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &rogueAPs); err != nil {
		log.Println("ERROR: " + err.Error())
		return rogueAPs, err
	}

	return rogueAPs, nil
}

//GetPortProfiles - Retrieves a list of configured port profiles
func (c *Unifi) GetPortProfiles(ctx context.Context) (PortProfiles, error) {
	portProfiles := PortProfiles{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/portconf", c.BaseURL, c.site), nil)

	if err != nil {
		return portProfiles, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &portProfiles); err != nil {
		log.Println("ERROR: " + err.Error())
		return portProfiles, err
	}

	return portProfiles, nil
}

//GetRadiusProfiles - Retrieves a list of configured port profiles
func (c *Unifi) GetRadiusProfiles(ctx context.Context) (RadiusProfiles, error) {
	radiusProfiles := RadiusProfiles{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/radiusprofile", c.BaseURL, c.site), nil)

	if err != nil {
		return radiusProfiles, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &radiusProfiles); err != nil {
		log.Println("ERROR: " + err.Error())
		return radiusProfiles, err
	}

	return radiusProfiles, nil
}

//GetRadiusAccounts - Retrieves a list of configured port profiles
func (c *Unifi) GetRadiusAccounts(ctx context.Context) (RadiusAccounts, error) {
	radiusAccounts := RadiusAccounts{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/account", c.BaseURL, c.site), nil)

	if err != nil {
		return radiusAccounts, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &radiusAccounts); err != nil {
		log.Println("ERROR: " + err.Error())
		return radiusAccounts, err
	}

	return radiusAccounts, nil
}

//GetPortForwardRules - Retrieves a list of configured port profiles
func (c *Unifi) GetPortForwardRules(ctx context.Context) (PortForwardRules, error) {
	portForwardRules := PortForwardRules{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/rest/portforward", c.BaseURL, c.site), nil)

	if err != nil {
		return portForwardRules, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &portForwardRules); err != nil {
		log.Println("ERROR: " + err.Error())
		return portForwardRules, err
	}

	return portForwardRules, nil
}

//GetRFChannels - Retrieves RF Channel details
func (c *Unifi) GetRFChannels(ctx context.Context) (RFChannels, error) {
	rfChannels := RFChannels{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/stat/current-channel", c.BaseURL, c.site), nil)

	if err != nil {
		return rfChannels, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &rfChannels); err != nil {
		log.Println("ERROR: " + err.Error())
		return rfChannels, err
	}

	return rfChannels, nil
}

//GetCountryCodes - Retrieves the list of country codes
func (c *Unifi) GetCountryCodes(ctx context.Context) (CountryCodes, error) {
	countryCodes := CountryCodes{}

	req, err := http.NewRequest("GET", fmt.Sprintf("%s/s/%s/stat/ccode", c.BaseURL, c.site), nil)

	if err != nil {
		return countryCodes, err
	}

	req = req.WithContext(ctx)

	if err := c.sendRequest(req, &countryCodes); err != nil {
		log.Println("ERROR: " + err.Error())
		return countryCodes, err
	}

	return countryCodes, nil
}

// There must be a better way of doing this?
func (c *Unifi) loginToken() (string, error) {

	loginToken := ""

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	url := baseURL + "/login"

	payload := strings.NewReader("{\"username\":\"" + c.userName + "\",\"password\":\"" + c.password + "\"}")

	req, _ := http.NewRequest("POST", url, payload)

	req.Header.Add("Content-Type", "text/plain")
	req.Header.Add("User-Agent", "Golang")
	req.Header.Add("Accept", "*/*")
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("accept-encoding", "gzip, deflate")
	req.Header.Add("content-length", "44")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Add("cache-control", "no-cache")

	res, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Println("ERROR: " + err.Error())
		return "", err
	}

	defer res.Body.Close()

	authResponse := AuthResponse{}

	if err = json.NewDecoder(res.Body).Decode(&authResponse); err != nil {
		return "", err
	}

	if authResponse.Meta.Rc != "ok" {
		return "", errors.New("API Authentication Failed")
	}

	//body, _ := ioutil.ReadAll(res.Body)
	//log.Println("Auth Response: " + string(body))

	for _, cookie := range res.Cookies() {
		if cookie.Name == "unifises" {
			loginToken = cookie.Value
		}
	}

	return loginToken, nil
}

func (c *Unifi) sendRequest(req *http.Request, v interface{}) error {

	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")

	// Get Login Token
	token, err := c.loginToken()

	if err != nil {
		return err
	}

	// Create the login cookie. Not sure what the expiry time should be.
	// Dont think it matters since we grab a new one each time. TODO: Investigate options here.
	expire := time.Now().Add(30 * time.Minute)
	cookie := http.Cookie{
		Name:    "unifises",
		Value:   token,
		Expires: expire,
	}

	cookies := []*http.Cookie{&cookie}
	c.HTTPClient.Jar.SetCookies(req.URL, cookies)
	res, err := c.HTTPClient.Do(req)

	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		return fmt.Errorf("HTTP Error, Status code: %d", res.StatusCode)
	}

	if err = json.NewDecoder(res.Body).Decode(&v); err != nil {
		return err
	}

	return nil
}
