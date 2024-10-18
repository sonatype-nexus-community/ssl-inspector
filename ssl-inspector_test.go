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
		valid, messages, err := checkSSL("badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, 0, len(messages))
		assert.True(t, valid)
	})

	t.Run("expiredAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("expired.badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.Equal(t, "Certifcate for CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard is invalid because: Certificate expired", messages[0])
		assert.False(t, valid)
	})

	t.Run("expiredAndTrustedByOSWithPort", func(t *testing.T) {
		valid, messages, err := checkSSL("expired.badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.Equal(t, "Certifcate for CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard is invalid because: Certificate expired", messages[0])
		assert.False(t, valid)
	})

	t.Run("wrongHostAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("wrong.host.badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.Equal(t, "Certifcate for CN=*.badssl.com is not valid for wrong.host.badssl.com:443", messages[0])
		assert.False(t, valid)
	})

	t.Run("unknownAuthorityAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("self-signed.badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.Equal(t, "Certifcate for CN=*.badssl.com,O=BadSSL,L=San Francisco,ST=California,C=US is not trusted. This could be because:\n\t1. It is self-signed\n\t2. It is signed by an unknown authority\n\t3. The CA that signed this certificate is not a invalid Certificate Authority\n\t\n\tIt was signed by: *.badssl.com", messages[0])
		assert.False(t, valid)
	})

	t.Run("untrustedRootAndTrustedByOS", func(t *testing.T) {
		valid, messages, err := checkSSL("untrusted-root.badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, 1, len(messages))
		assert.False(t, valid)
	})

	if runtime.GOOS == "darwin" {
		// Looks like Windows and Linux do not do realtime CRL checks
		t.Run("revokedAndTrustedByOS", func(t *testing.T) {
			valid, messages, err := checkSSL("revoked.badssl.com:443")
			assert.NoError(t, err)
			assert.Equal(t, 1, len(messages))
			assert.Equal(t, "Certifcate for revoked.badssl.com:443 is invalid because: tls: failed to verify certificate: x509: “revoked.badssl.com” certificate is revoked", messages[0])
			assert.False(t, valid)
		})
	}
}

func TestSingleCert(t *testing.T) {
	valid, messages, err := checkSSL("expired.badssl.com:443")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(messages))
	for _, m := range messages {
		println(m)
	}
	assert.False(t, valid)
}

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

	t.Run("ldapsPortSpecified", func(t *testing.T) {
		domain, err := validateEndpoint("ldaps://revoked.badssl.com:443")
		assert.NoError(t, err)
		assert.Equal(t, "revoked.badssl.com:443", *domain)
	})
}
