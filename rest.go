package goawsutil

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// AWSClient is a deminius AWS Client that follows the REST API
type AWSClient struct {
	Service    string
	HTTPClient *http.Client
	Signer     *AWSV4Signer
}

// ErrorResponse contains error information from an error response
type ErrorResponse struct {
	Code      string
	Message   string
	Resource  string
	RequestID string `xml:"RequestId"`
}

// NewAWSClient is a AWSClient constructor
func NewAWSClient(service string, cred *Credentials, client *http.Client) *AWSClient {
	if client == nil {
		client = http.DefaultClient
	}

	return &AWSClient{
		Service:    service,
		HTTPClient: client,
		Signer:     NewAWSV4Signer(cred),
	}
}

// Get does a HTTP GET and signs the request
func (c *AWSClient) Get(urlStr string, xheaders map[string]string) (*http.Response, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	regionName := RegionFromURL(u)
	if regionName == "" {
		return nil, fmt.Errorf("URL does not appear to be an S3 endpoint: %s", urlStr)

	}

	headers := make(http.Header)
	if xheaders != nil {
		for k, v := range xheaders {
			headers.Set(k, v)
		}
	}
	req := http.Request{
		Method:     "GET",
		URL:        u,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       nil,
		Header:     headers,
	}

	now := time.Now().UTC()
	c.Signer.Prepare(&req, []byte{}, now)
	c.Signer.Sign(&req, []byte{}, regionName, c.Service, now)

	resp, err := c.HTTPClient.Do(&req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("could not parse HTTP repsonse error: %s", err)
		}
		var errResp ErrorResponse
		err = xml.Unmarshal(data, &errResp)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal HTTP repsonse error: %s", err)
		}
		return nil, fmt.Errorf("HTTP Response Error: Code: %s, Message: %s", errResp.Code, errResp.Message)
	}
	return resp, nil
}

// Put does an HTTP PUT request to an S3 Asset
func (c *AWSClient) Put(urlStr string, xheaders map[string]string, body []byte) (*http.Response, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}
	regionName := RegionFromURL(u)
	if regionName == "" {
		return nil, fmt.Errorf("URL does not appear to an S3 endpoint: %s", urlStr)
	}

	headers := make(http.Header)
	headers.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	// override
	if xheaders != nil {
		for k, v := range xheaders {
			headers.Set(k, v)
		}
	}

	req := http.Request{
		Method:        "PUT",
		URL:           u,
		ProtoMajor:    1,
		ProtoMinor:    1,
		ContentLength: int64(len(body)),
		Header:        headers,
		Body:          ioutil.NopCloser(bytes.NewReader(body)),
	}
	now := time.Now().UTC()
	c.Signer.Prepare(&req, body, now)
	c.Signer.Sign(&req, body, regionName, c.Service, now)

	resp, err := c.HTTPClient.Do(&req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("could not parse HTTP repsonse error: %s", err)
		}
		var errResp ErrorResponse
		err = xml.Unmarshal(data, &errResp)
		if err != nil {
			return nil, fmt.Errorf("could not unmarshal HTTP repsonse error: %s", err)
		}
		return nil, fmt.Errorf("HTTP Response Error: Code: %s, Message: %s", errResp.Code, errResp.Message)
	}
	return resp, nil
}
