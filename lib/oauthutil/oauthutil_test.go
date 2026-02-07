package oauthutil

import (
	"testing"
)

func TestNormalizeAuthCode(t *testing.T) {
	// Sample base64-encoded JSON that represents a typical OAuth token.
	// This needs to be long enough to be the longest blob even with surrounding marker text.
	sampleToken := "eyJ0b2tlbiI6InRlc3RfdG9rZW5fdmFsdWVfd2l0aF9leHRyYV9kYXRhX3RvX21ha2VfaXRfbG9uZ19lbm91Z2hfZm9yX3Rlc3RpbmdfcHVycG9zZXMifQ"

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean input",
			input:    sampleToken,
			expected: sampleToken,
		},
		{
			name:     "with trailing newline",
			input:    sampleToken + "\n",
			expected: sampleToken,
		},
		{
			name:     "with config_token> prompt",
			input:    "config_token> " + sampleToken,
			expected: sampleToken,
		},
		{
			name:     "with token= prefix",
			input:    "token=" + sampleToken,
			expected: sampleToken,
		},
		{
			name:     "with embedded newlines (terminal wrapping)",
			input:    sampleToken[:20] + "\n" + sampleToken[20:],
			expected: sampleToken,
		},
		{
			name:     "with paste markers",
			input:    "Paste the following into your remote machine --->\n" + sampleToken + "\n<---End paste",
			expected: sampleToken,
		},
		{
			name:     "heavily wrapped (every 10 chars)",
			input:    insertNewlines(sampleToken, 10),
			expected: sampleToken,
		},
		{
			name:     "with multiple whitespace types",
			input:    "\t  " + sampleToken[:15] + "\r\n" + sampleToken[15:] + "  \t",
			expected: sampleToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeAuthCode(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeAuthCode() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// insertNewlines inserts a newline every n characters
func insertNewlines(s string, n int) string {
	var result string
	for i := 0; i < len(s); i += n {
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		result += s[i:end]
		if end < len(s) {
			result += "\n"
		}
	}
	return result
}
