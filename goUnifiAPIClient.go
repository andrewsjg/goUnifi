package gounifi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
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
