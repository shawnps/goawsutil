package goawsutil

import (
	"net/url"
	"strings"
)

// S3RegionEndpoints is map of RegionName to RegionEndpoint
var S3RegionEndpoints = map[string]string{
	"us-gov-west-1":  "s3-fips-us-gov-west-1.amazonaws.com",
	"us-east-1":      "s3.amazonaws.com",
	"us-west-1":      "s3-us-west-1.amazonaws.com",
	"us-west-2":      "s3-us-west-2.amazonaws.com",
	"eu-west-1":      "s3-eu-west-1.amazonaws.com",
	"ap-southeast-1": "s3-ap-southeast-1.amazonaws.com",
	"ap-southeast-2": "s3-ap-southeast-2.amazonaws.com",
	"ap-northeast-1": "s3-ap-northeast-1.amazonaws.com",
	"sa-east-1":      "s3-sa-east-1.amazonaws.com",
	"cn-north-1":     "s3-cn-north-1.amazonaws.com.cn",
}

// S3RegionFromURL determines the region from a S3 URL or empty string
//  if it does not appear to be a S3 endpoint
func S3RegionFromURL(u *url.URL) string {
	host := u.Host
	for k, v := range S3RegionEndpoints {
		if strings.HasSuffix(host, v) {
			return k
		}
	}
	return ""
}
