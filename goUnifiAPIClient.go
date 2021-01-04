package gounifi

import (
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
		panic("Unable to create API Client. Cookie Jar creation failed: " + err.Error())
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
