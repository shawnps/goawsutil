package goawsutil

import (
	"crypto/hmac"
	"crypto/sha256"
)

func makemac(message string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// GenerateSigningKey generates a single signing key
func GenerateSigningKey(key string, dateStamp string, regionName string, serviceName string) []byte {
	keyDate := makemac(dateStamp, []byte("AWS4"+key))
	keyRegion := makemac(regionName, keyDate)
	keyService := makemac(serviceName, keyRegion)
	keySigning := makemac("aws4_request", keyService)
	return keySigning
}
