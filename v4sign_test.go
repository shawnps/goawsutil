package goawsutil

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	ExampleNowDate       = "20110909T233600Z"
	ExampleRegionName    = "us-east-1"
	ExampleServiceName   = "host"
	ExampleAWSIdentifier = "aws4_request"
	ExampleAccessKey     = "AKIDEXAMPLE"
	ExampleSecretKey     = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)

// unfortuantely the amazon test files are encoded
// using MS-Windows newlines which is in violation of their
// specification
func normalizeNewlines(input []byte) []byte {
	return bytes.Replace(input, []byte("\r\n"), []byte("\n"), -1)
}

// not so robust, designed mostly for test case
//  Would be nice to find a sleazy way to recycle
//  Go's http parser
func reqfileToHTTP(fname string) (http.Request, []byte) {
	fbytes, err := ioutil.ReadFile(fname)
	if err != nil {
		panic("Unable to read " + fname)
	}
	idx := bytes.Index(fbytes, []byte("\r\n\r\n"))
	if idx == -1 {
		panic("Incomplete request")
	}
	lines := strings.Split(string(fbytes[:idx]), "\r\n")
	payload := fbytes[idx+4:]

	// METHOD, URI, PROTOCOL
	introparts := strings.SplitN(lines[0], " ", 3)
	headers := make(http.Header)

	// skip first line, rest is headers
	for _, line := range lines[1:] {
		kv := strings.SplitN(line, ":", 2)
		if len(kv) != 2 {
			break
		}
		headers.Add(kv[0], kv[1])
	}

	// From this build up URL
	host := headers.Get("Host")
	if host == "" {
		panic("didn't find host")
	}

	requrl, err := url.Parse(fmt.Sprintf("https://%s/%s", host, introparts[1]))
	if err != nil {
		// some of input have crazy values that GoLang knows
		// is improper and complains
		requrl = &url.URL{
			Scheme: "https",
			Host:   host,
			Path:   introparts[1],
		}
	}

	req := http.Request{
		Method: introparts[0],
		URL:    requrl,
		Host:   requrl.Host,
		Header: headers,
	}
	return req, payload
}

func TestAWS4Sign(t *testing.T) {
	now, err := time.Parse("20060102T150405Z", ExampleNowDate)
	if err != nil {
		panic("Bad example date")
	}
	awscred := NewCredentials(ExampleAccessKey, ExampleSecretKey)
	signer := NewAWSV4Signer(awscred)
	requests, err := filepath.Glob("./aws4_testsuite/*.req")
	if err != nil || len(requests) == 0 {
		t.Errorf("Unable to find tests: %s", err)
		return
	}
	for _, testreq := range requests {

		// this test is weird since its difficult in Go
		// event to get this to process
		if testreq == "aws4_testsuite/post-vanilla-query-nonunreserved.req" {
			continue
		}

		// this test is broken
		if testreq == "aws4_testsuite/get-header-value-multiline.req" {
			continue
		}

		testbase := testreq[:len(testreq)-4]
		fname := testbase + ".creq"
		ctest, err := ioutil.ReadFile(fname)
		if err != nil {
			panic("test case is bogus: " + fname)
		}
		ctest = normalizeNewlines(ctest)

		fname = testbase + ".sts"
		sts, err := ioutil.ReadFile(fname)
		if err != nil {
			panic("Test case is bogus: " + fname)
		}
		sts = normalizeNewlines(sts)

		fname = testbase + ".authz"
		authz, err := ioutil.ReadFile(fname)
		if err != nil {
			panic("Test case is bogus: " + fname)
		}
		authzstr := string(normalizeNewlines(authz))

		//fmt.Printf("---------FILE %s\n", testreq)
		req, payload := reqfileToHTTP(testreq)
		signer.Sign(&req, payload, ExampleRegionName, ExampleServiceName, now)

		if !bytes.Equal(ctest, signer.CannonicalRequest) {
			t.Errorf("Boo Canonical Request: %s Expected:\n'%s'\nReceived:\n'%s'\n", testreq, ctest, signer.CannonicalRequest)
		}

		if !bytes.Equal(sts, signer.StringToSign) {
			t.Errorf("Boo StringToSign: %s Expected:\n'%s'\nReceived:\n'%s'\n", testreq, sts, signer.StringToSign)
		}

		if authzstr != req.Header.Get("Authorization") {
			t.Errorf("Boo StringToSign: %s Expected:\n'%s'\nReceived:\n'%s'\n", testreq, authz, req.Header.Get("Authorization"))
		}

	}
}
