package goawsutil

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

// S3Client is a deminius S3 Client that follows the REST API
type AWSClient struct {
	Service    string
	HTTPClient *http.Client
	Signer     *AWSV4Signer
}

// NewS3Client is a S3Client constructor
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
		return nil, fmt.Errorf("URL does not appear to an S3 endpoint: %s", urlStr)

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
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		data, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP Response Error: %s", string(data))
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
		ContentLength: len(body),
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
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		data, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP Response Error: %s", string(data))
	}
	return resp, nil
}
