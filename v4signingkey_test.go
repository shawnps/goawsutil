package goawsutil

import (
	"bytes"
	"testing"
)

// http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html

func TestAWS4SigningKey(t *testing.T) {
	const (
		ExampleSecret  = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		ExampleDate    = "20110909"
		ExampleRegion  = "us-east-1"
		ExampleService = "iam"
	)

	expected := []byte{152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43, 171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229, 169, 76, 144, 239, 209, 227, 176, 231}

	actual := GenerateSigningKey(ExampleSecret, ExampleDate, ExampleRegion, ExampleService)

	if !bytes.Equal(expected, actual) {
		t.Errorf("Sample Signing Key test failed")
	}
}
