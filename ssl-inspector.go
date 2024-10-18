/**
 * Copyright (c) 2024-present Paul Horton (@madpah)
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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	currentRuntime string = runtime.GOOS
	debugLogging   bool   = false
	testEndpoint   string
	version        string = "development"
)

func init() {
	flag.BoolVar(&debugLogging, "X", false, "Enable debug logging")
	flag.StringVar(&testEndpoint, "endpoint", "", "Endpoint to inspect SSL on. Can be https://domain (assuming port 443) or a domain and port after a colon (:)")
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: ssl-inspector [OPTOINS]\n")
	flag.PrintDefaults()
}

func main() {
	log.SetOutput(os.Stdout)
	if debugLogging {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	// log.SetFormatter(&util.LogFormatter{Module: "SCANNER"})

	flag.Usage = usage
	flag.Parse()

	println("")
	println(fmt.Sprintf("	Running on:		%s/%s", currentRuntime, runtime.GOARCH))
	println(fmt.Sprintf("	Scanner Version: 	%s", version))
	println("")

	validatedEndpoint, err := validateEndpoint(testEndpoint)
	if err != nil {
		println("Supplied endpoint is not well formed")
		os.Exit(1)
	}

	// Load System Root CAs
	// rootCAs, _ := x509.SystemCertPool()
	// if rootCAs == nil {
	// 	rootCAs = x509.NewCertPool()
	// }

	valid, messages, err := checkSSL(fmt.Sprintf("https://%s", *validatedEndpoint))
	if err != nil {
		println(fmt.Sprintf("Error performing checks: %v", err))
		os.Exit(1)
	}

	if valid {
		println(fmt.Sprintf("All checked passed connecting to %s", *validatedEndpoint))
	} else {
		println(fmt.Sprintf("!!! Connection to %s will not work. !!!", *validatedEndpoint))
		println("")
		println(fmt.Sprintf("There are %d certificate errors connecting to %s. They are:", len(messages), *validatedEndpoint))
		println("")
		for i, m := range messages {
			println(fmt.Sprintf(" [%d] - %s", (i + 1), m))
		}
	}
	println("")
}

/**
 * Connect to the given endpoint and check various Certificate related items
 *
 * Returns true/false, list of messages and optionally an error.
 */
func checkSSL(endpoint string) (bool, []string, error) {
	messages := make([]string, 0)
	config := &tls.Config{
		// InsecureSkipVerify: *insecure,
		// RootCAs: rootCAs,
	}

	tr := &http.Transport{TLSClientConfig: config}
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return false, messages, err
	}

	_, err = client.Do(req)

	if err != nil {
		var certValidationError *tls.CertificateVerificationError
		var netUrlError *url.Error
		if errors.As(err, &netUrlError) {
			//println("url.Error")
			if errors.As(netUrlError.Err, &certValidationError) {
				//println("tls.CertificateVerificationError")
				handled := false
				if hostnameError, ok := certValidationError.Err.(x509.HostnameError); ok {
					messages = append(messages, fmt.Sprintf("Certifcate for %s is not valid for %s", hostnameError.Certificate.Subject, endpoint))
					handled = true
				}

				if certInvalidError, ok := certValidationError.Err.(x509.CertificateInvalidError); ok {
					messages = append(messages, fmt.Sprintf("Certifcate for %s is invalid because: %s", certInvalidError.Cert.Subject, getInvalidReason(int(certInvalidError.Reason))))
					handled = true
				}

				if unknownAuthorityError, ok := certValidationError.Err.(x509.UnknownAuthorityError); ok {
					messages = append(messages, fmt.Sprintf(`Certifcate for %s is not trusted. This could be because:
	1. It is self-signed
	2. It is signed by an unknown authority
	3. The CA that signed this certificate is not a invalid Certificate Authority
	
	It was signed by: %s`, unknownAuthorityError.Cert.Subject, unknownAuthorityError.Cert.Issuer.CommonName))
					handled = true
				}

				if !handled {
					messages = append(messages, fmt.Sprintf("Certifcate for %s is invalid because: %s", endpoint, certValidationError.Error()))
				}
			}
		} else {
			println("Failed making request")
			println(err.Error)
		}

		return false, messages, nil
	}

	return true, messages, nil
}

/**
 * Validates the supplied endpoint returning the domain:port or error.
 */
func validateEndpoint(endpoint string) (*string, error) {
	// Attempt to straight parse what was provided
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	if u.Scheme == "" || u.Host == "" {
		// Failed to parse - prepend with https://
		log.Debug("Reparsing with https:// prepended")
		u, err = url.Parse(fmt.Sprintf("https://%s", endpoint))
		if err != nil {
			return nil, err
		}
	}

	var h string
	if u.Scheme == "" {
		log.Debug("No Scheme - assume port 443")
		if u.Host == "" {
			h = fmt.Sprintf("%s:443", endpoint)
		} else {
			h = fmt.Sprintf("%s:443", u.Host)
		}
	} else if u.Scheme == "https" && !strings.Contains(u.Host, ":") {
		log.Debug("HTTPS scheme with no port - assume 443")
		h = fmt.Sprintf("%s:443", u.Host)
	} else {
		h = u.Host
	}

	return &h, nil
}

/**
 * Decodes InvalidReason from x509.verify
 */
func getInvalidReason(invalidReason int) string {
	r := int(invalidReason)

	switch r {
	case int(x509.NotAuthorizedToSign):
		return "Signed by cerificate that is not marked as a CA"

	case int(x509.Expired):
		return "Certificate expired"

	case int(x509.CANotAuthorizedForThisName):
		return "CANotAuthorizedForThisName results when an intermediate or root certificate has a name constraint which doesn't permit a DNS or other name (including IP address) in the leaf certificate."

	case int(x509.TooManyIntermediates):
		return "TooManyIntermediates results when a path length constraint is violated."

	case int(x509.IncompatibleUsage):
		return "Incompatible Usage results when the certificate's key usage indicates that it may only be used for a different purpose"

	case int(x509.NameMismatch):
		return "NameMismatch results when the subject name of a parent certificate does not match the issuer name in the child."

	case int(x509.UnconstrainedName):
		return "UnconstrainedName results when a CA certificate contains permitted name constraints, but leaf certificate contains a name of an unsupported or unconstrained type."

	case int(x509.TooManyConstraints):
		return "TooManyConstraints results when the number of comparison operations needed to check a certificate exceeds the limit set by VerifyOptions.MaxConstraintComparisions"

	case int(x509.CANotAuthorizedForExtKeyUsage):
		return "CANotAuthorizedForExtKeyUsage results when an intermediate or root certificate does not permit a requested extended key usage."
	}

	return "Unknown"
}
