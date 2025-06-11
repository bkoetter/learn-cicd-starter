package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		expectedKey   string
		expectedError error
	}{
		{
			name:          "no header",
			authHeader:    "",
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "malformed header - missing ApiKey prefix",
			authHeader:    "Bearer sometoken",
			expectedKey:   "",
			expectedError: errMalformedHeader(),
		},
		{
			name:          "malformed header - only prefix",
			authHeader:    "ApiKey",
			expectedKey:   "",
			expectedError: errMalformedHeader(),
		},
		{
			name:          "valid header",
			authHeader:    "ApiKey abc123",
			expectedKey:   "abc123",
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			key, err := GetAPIKey(headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if (err != nil && tt.expectedError == nil) || (err == nil && tt.expectedError != nil) || (err != nil && tt.expectedError != nil && err.Error() != tt.expectedError.Error()) {
				t.Errorf("expected error %v, got %v", tt.expectedError, err)
			}
		})
	}
}

func errMalformedHeader() error {
	return errors.New("malformed authorization header")
}
