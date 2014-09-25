package goawsutil

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// reference
//　http://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
// http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html

// AWSV4Signer contains state in the process of making a V4 signing
type AWSV4Signer struct {
	cred *Credentials

	// Artifacts.. only used for testing
	CannonicalRequest []byte
	StringToSign      []byte
}

// NewAWSV4Signer is a contructor.
func NewAWSV4Signer(awscred *Credentials) *AWSV4Signer {
	return &AWSV4Signer{
		cred: awscred,
	}
}
func (a *AWSV4Signer) cannonicalizePath(u *url.URL) string {

	cleanpath := u.Path
	cleanpath = path.Clean(cleanpath)
	cleanpath = URLEscape(cleanpath)

	// add back ending "/" if it got nuked
	if cleanpath != "/" && strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(cleanpath, "/") {
		cleanpath = cleanpath + "/"
	}

	return cleanpath
}

func (a *AWSV4Signer) cannonicalizeQuery(u *url.URL) string {
	// assume duplicates in query string are rare
	qsv := make([]string, 0, len(u.Query()))
	for k, vlist := range u.Query() {
		for _, v := range vlist {
			qsv = append(qsv, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	sort.Strings(qsv)
	return strings.Join(qsv, "&")
}

// Sign does a single signature request
func (a *AWSV4Signer) Sign(req *http.Request, payload []byte, regionName string, serviceName string, now time.Time) {

	cannonicalQuery := a.cannonicalizeQuery(req.URL)
	cannonicalPath := a.cannonicalizePath(req.URL)

	// To create the canonical headers list, convert all header names to
	// lowercase and trim excess white space characters out of the header
	// values. When you trim, remove leading spaces and trailing spaces,
	// and convert sequential spaces in the value to a single space.
	// However, do not remove extra spaces from any values that are inside
	// quotation marks.

	// Host is required but is a bit weird in go lang (3 places to specify it)
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	host := req.Header.Get("Host")
	if host == "" {
		if req.Host != "" {
			host = req.Host
		} else {
			host = req.URL.Host
		}
		req.Header.Set("Host", host)
	}

	cannonicalHeaderMap := make(map[string]string)
	for k, vlist := range req.Header {
		cvlist := make([]string, len(vlist))
		for pos, v := range vlist {
			// TODO cannonicalize V
			cvlist[pos] = strings.TrimSpace(v)
		}
		sort.Strings(cvlist)
		cannonicalHeaderMap[strings.ToLower(k)] = strings.Join(cvlist, ",")
	}
	// now make signedHeadersList
	signedHeadersList := make([]string, 0, len(cannonicalHeaderMap))
	for k := range cannonicalHeaderMap {
		signedHeadersList = append(signedHeadersList, k)
	}
	sort.StringSlice(signedHeadersList).Sort()
	signedHeaders := strings.Join(signedHeadersList, ";")
	rawHashedPayload := sha256.Sum256(payload)

	buf := bytes.Buffer{}
	buf.WriteString(req.Method)
	buf.WriteByte('\n')
	buf.WriteString(cannonicalPath)
	buf.WriteByte('\n')
	buf.WriteString(cannonicalQuery)
	buf.WriteByte('\n')

	for _, k := range signedHeadersList {
		buf.WriteString(k)
		buf.WriteByte(':')
		buf.WriteString(cannonicalHeaderMap[k])
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	buf.WriteString(signedHeaders)
	buf.WriteByte('\n')
	buf.WriteString(hex.EncodeToString(rawHashedPayload[:]))
	a.CannonicalRequest = buf.Bytes()
	cannonicalRequestHash := sha256.Sum256(a.CannonicalRequest)

	// TASK 2
	// Create a String to Sign for Signature Version 4

	isodate := now.UTC().Format("20060102T150405Z")
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", isodate[:8], regionName, serviceName)
	buf2 := bytes.Buffer{}
	buf2.WriteString("AWS4-HMAC-SHA256")
	buf2.WriteByte('\n')
	buf2.WriteString(isodate)
	buf2.WriteByte('\n')
	buf2.WriteString(credentialScope)
	buf2.WriteByte('\n')
	buf2.WriteString(hex.EncodeToString(cannonicalRequestHash[:]))
	// no ending newline
	a.StringToSign = buf2.Bytes()

	// TASK 3
	// Calculate the AWS Signature Version 4
	signingKey := a.cred.SigningKey(isodate[:8], regionName, serviceName)
	signatureBytes := makemac(string(a.StringToSign), signingKey)
	signatureHex := hex.EncodeToString(signatureBytes[:])

	// TASK 4
	// Task 4: Add the Signing Information to the Request
	// Authorization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c
	authValue := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		a.cred.AccessKey,
		credentialScope,
		signedHeaders,
		signatureHex,
	)
	req.Header.Set("Authorization", authValue)

}
