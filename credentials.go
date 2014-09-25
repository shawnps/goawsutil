package goawsutil

import (
	"time"
)

// SigningKey is a signing key, expiration pair
type SigningKey struct {
	Key     []byte
	Expires time.Time
}

// Credentials is for AWS Credentials
//
// TODO: Token support
type Credentials struct {
	AccessKey string
	SecretKey string

	// If nil, get current time from System
	NowTime     *time.Time
	KeyLifetime time.Duration

	// TODO MUTEX
	SigningKeyCache map[string]SigningKey
}

// NewCredentials is a constructor
func NewCredentials(accesskey, secretkey string) *Credentials {
	return &Credentials{
		AccessKey:       accesskey,
		SecretKey:       secretkey,
		SigningKeyCache: make(map[string]SigningKey),
	}
}

func (c *Credentials) now() time.Time {
	if c.NowTime == nil {
		return time.Now().UTC()
	}
	return *c.NowTime
}

// SigningKey generates or gets a key from cache
// May pull from cache
func (c *Credentials) SigningKey(dateStamp string, regionName string, serviceName string) []byte {
	// LOCK
	// DEFER UNLOCK
	now := c.now()

	cachekey := regionName + "-" + serviceName
	sk, ok := c.SigningKeyCache[cachekey]
	if ok && sk.Expires.After(now) {
		return sk.Key
	}
	lifetime := c.KeyLifetime
	if lifetime == 0 {
		lifetime = time.Duration(24*6) * time.Hour
	}
	key := GenerateSigningKey(c.SecretKey, dateStamp, regionName, serviceName)

	sk = SigningKey{
		Key:     key,
		Expires: now.Add(lifetime),
	}
	c.SigningKeyCache[cachekey] = sk
	return sk.Key
}
