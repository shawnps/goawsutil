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
func (a *AWSV4Signer) canonicalizePath(u *url.URL) string {

	cleanpath := u.Path
	cleanpath = path.Clean(cleanpath)

	// do not escape '/'
	cleanpath = URLEscape(cleanpath, false)

	// add back ending "/" if it got nuked
	if cleanpath != "/" && strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(cleanpath, "/") {
		cleanpath = cleanpath + "/"
	}

	return cleanpath
}

func (a *AWSV4Signer) canonicalizeQuery(u *url.URL) string {
	// assume duplicates in query string are rare
	qsv := make([]string, 0, len(u.Query()))
	for k, vlist := range u.Query() {
		for _, v := range vlist {
			// yes do escape '/'
			qsv = append(qsv, URLEscape(k, true)+"="+URLEscape(v, true))
		}
	}
	sort.Strings(qsv)
	return strings.Join(qsv, "&")
}

func (a *AWSV4Signer) Prepare(req *http.Request, payload []byte, now time.Time) {
	rawHashedPayload := sha256.Sum256(payload)
	req.Header.Set("x-amz-content-sha256", hex.EncodeToString(rawHashedPayload[:]))

	req.Header.Set("x-amz-date", now.UTC().Format("20060102T150405Z"))
}

// Sign does a single signature request
func (a *AWSV4Signer) Sign(req *http.Request, payload []byte, regionName string, serviceName string, now time.Time) {

	canonicalQuery := a.canonicalizeQuery(req.URL)
	canonicalPath := a.canonicalizePath(req.URL)

	// To create the canonical headers list, convert all header names to
	// lowercase and trim excess white space characters out of the header
	// values. When you trim, remove leading spaces and trailing spaces,
	// and convert sequential spaces in the value to a single space.
	// However, do not remove extra spaces from any values that are inside
	// quotation marks.

	// Host is required but is a bit weird in go lang (3 places to specify it)
	host := req.Header.Get("Host")
	if host == "" {
		if req.Host != "" {
			host = req.Host
		} else {
			host = req.URL.Host
		}
		req.Header.Set("Host", host)
	}

	canonicalHeaderMap := make(map[string]string)
	for k, vlist := range req.Header {
		cvlist := make([]string, len(vlist))
		for pos, v := range vlist {
			// TODO canonicalize V
			cvlist[pos] = strings.TrimSpace(v)
		}
		sort.Strings(cvlist)
		canonicalHeaderMap[strings.ToLower(k)] = strings.Join(cvlist, ",")
	}
	// now make signedHeadersList
	signedHeadersList := make([]string, 0, len(canonicalHeaderMap))
	for k := range canonicalHeaderMap {
		signedHeadersList = append(signedHeadersList, k)
	}
	sort.StringSlice(signedHeadersList).Sort()
	signedHeaders := strings.Join(signedHeadersList, ";")

	payloadHash := req.Header.Get("x-amz-content-sha256")
	if payloadHash == "" {
		rawHashedPayload := sha256.Sum256(payload)
		payloadHash = hex.EncodeToString(rawHashedPayload[:])
	}

	buf := bytes.Buffer{}
	buf.WriteString(req.Method)
	buf.WriteByte('\n')
	buf.WriteString(canonicalPath)
	buf.WriteByte('\n')
	buf.WriteString(canonicalQuery)
	buf.WriteByte('\n')

	for _, k := range signedHeadersList {
		buf.WriteString(k)
		buf.WriteByte(':')
		buf.WriteString(canonicalHeaderMap[k])
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	buf.WriteString(signedHeaders)
	buf.WriteByte('\n')
	buf.WriteString(payloadHash)
	a.CannonicalRequest = buf.Bytes()
	canonicalRequestHash := sha256.Sum256(a.CannonicalRequest)

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
	buf2.WriteString(hex.EncodeToString(canonicalRequestHash[:]))
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
