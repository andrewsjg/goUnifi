package gounifi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"golang.org/x/net/publicsuffix"
	"time"
)

const (
	baseURL = "https://unifi:8443/api"
)

// Client - API Client
type Client struct {
	BaseURL    string
	userName   string
	password   string
	site       string
	HTTPClient *http.Client
}

// NewClient - Create a new API Client
func NewClient(username string, password string, site string) *Client {
	
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil { // TODO: error handling }
		
	return &Client{
		BaseURL:    baseURL,
		userName:   username,
		password:   password,
		site:       site,
		HTTPClient: &http.Client{Timeout: time.Minute, Jar: jar},
	}

}

//SiteHealth Calls /api/s/default/stat/health
func (c *Client) SiteHealth(ctx context.Context) (*SiteHealth, error) {

	req, err := http.NewRequest("GET", fmt.Sprintf("%s//s/%s//stat//health", c.BaseURL, c.site), nil)

	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	result := SiteHealth{}

	if err := c.sendRequest(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) sendRequest(req *http.Request, v interface{}) error {

	
	// Do we have a login token?
	for _, cookie := range c.HTTPClient.Jar.Cookies() {
		fmt.Println(cookie.Name)
	}

	/*
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "application/json; charset=utf-8")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.apiKey))

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusBadRequest {
		var errRes errorResponse
		if err = json.NewDecoder(res.Body).Decode(&errRes); err == nil {
			return errors.New(errRes.Message)
		}

		return fmt.Errorf("unknown error, status code: %d", res.StatusCode)
	}

	fullResponse := successResponse{
		Data: v,
	}
	if err = json.NewDecoder(res.Body).Decode(&fullResponse); err != nil {
		return err
	} */

	return nil
}
