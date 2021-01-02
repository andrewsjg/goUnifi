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

//GetClients - Retrieves information about all active clients on the network
func (c *Unifi) GetClients(ctx context.Context) (Clients, error) {
	clients := Clients{}

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
