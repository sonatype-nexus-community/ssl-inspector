/**
 * Copyright (c) 2024-present Sonatype Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckSSL(t *testing.T) {
	t.Run("validAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("https://badssl.com")
		assert.NoError(t, err)
		assert.Equal(t, 0, len(messages))
		assert.True(t, valid)
	})

	t.Run("expiredAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("https://expired.badssl.com")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.False(t, valid)
	})

	t.Run("expiredAndTrustedByOSWithPort", func(t *testing.T) {
		valid, messages, err := checkSSL("https://expired.badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.False(t, valid)
	})

	t.Run("wrongHostAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("https://wrong.host.badssl.com")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.False(t, valid)
	})

	t.Run("unknownAuthorityAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("https://self-signed.badssl.com")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.False(t, valid)
	})

	t.Run("untrustedRootAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("https://untrusted-root.badssl.com")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.False(t, valid)
	})

	if runtime.GOOS != "linux" {
		// Looks like Linux does not do realtime CRL checks - at least on Ubuntu
		t.Run("revokedAndTrustedByOS", func(t *testing.T) {
			valid, messages, err := checkSSL("https://revoked.badssl.com")
			assert.NoError(t, err)
			assert.Equal(t, 1, len(messages))
			assert.False(t, valid)
		})
	}
}

// func TestSingleCert(t *testing.T) {
// 	valid, messages, err := checkSSL("https://revoked.badssl.com")
// 	assert.NoError(t, err)
// 	assert.Equal(t, 1, len(messages))
// 	for _, m := range messages {
// 		println(m)
// 	}
// 	assert.False(t, valid)
// }

func TestParseEndpoints(t *testing.T) {
	t.Run("httpsNoPortSpecified", func(t *testing.T) {
		domain, err := validateEndpoint("https://badssl.com")
		assert.NoError(t, err)
		assert.Equal(t, "badssl.com:443", *domain)
	})

	t.Run("httpsPortSpecified", func(t *testing.T) {
		domain, err := validateEndpoint("https://badssl.com:444")
		assert.NoError(t, err)
		assert.Equal(t, "badssl.com:444", *domain)
	})

	t.Run("noProtocolNoPortSpecified", func(t *testing.T) {
		domain, err := validateEndpoint("badssl.com")
		assert.NoError(t, err)
		assert.Equal(t, "badssl.com:443", *domain)
	})

	t.Run("noProtocolPortSpecified", func(t *testing.T) {
		domain, err := validateEndpoint("badssl.com:555")
		assert.NoError(t, err)
		assert.Equal(t, "badssl.com:555", *domain)
	})
}
