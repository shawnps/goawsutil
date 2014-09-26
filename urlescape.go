package goawsutil

// DO REWRITE USING ARRAY

// this was horked from google go lang source code
// BOO on goamz

// http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
// amazonShouldEscape returns true if byte should be escaped
func amazonShouldEscape(c byte) bool {
	return !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~')
}

// URLEscape does url escape in the cannonical way for Amazon
func URLEscape(s string) string {
	hexCount := 0

	for i := 0; i < len(s); i++ {
		if amazonShouldEscape(s[i]) {
			hexCount++
		}
	}

	if hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		if c := s[i]; amazonShouldEscape(c) {
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		} else {
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}
