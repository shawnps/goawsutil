package goawsutil

import (
	"net/url"
	"strings"
)

// S3RegionEndpoints is map of RegionName to RegionEndpoint
var RegionEndpoints = map[string]string{
	"us-gov-west-1":  "fips-us-gov-west-1.amazonaws.com",
	"us-east-1":      "s3.amazonaws.com",
	"us-west-1":      "us-west-1.amazonaws.com",
	"us-west-2":      "us-west-2.amazonaws.com",
	"eu-west-1":      "eu-west-1.amazonaws.com",
	"ap-southeast-1": "ap-southeast-1.amazonaws.com",
	"ap-southeast-2": "ap-southeast-2.amazonaws.com",
	"ap-northeast-1": "ap-northeast-1.amazonaws.com",
	"sa-east-1":      "sa-east-1.amazonaws.com",
	"cn-north-1":     "cn-north-1.amazonaws.com.cn",
}

// S3RegionFromURL determines the region from a S3 URL or empty string
//  if it does not appear to be a S3 endpoint
func RegionFromURL(u *url.URL) string {
	host := u.Host
	for k, v := range RegionEndpoints {
		if strings.HasSuffix(host, v) {
			return k
		}
	}
	return ""
}
