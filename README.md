# SSL Inspector

<!-- Badges Section -->

[![shield_gh-workflow-test]][link_gh-workflow-test]
[![shield_license]][license_file]

<!-- Add other badges or shields as appropriate -->

A small helpful portable program to test SSL connections.

## Installation

Grab the binary specific to your Operating System and Architecture from the [Releases Page](https://github.com/sonatype-nexus-community/ssl-inspector/releases).

Unpack it, and make sure the file is executable.

## Running

See all the options:

```
./ssl-inspector --help

Usage: ssl-inspector [OPTOINS]
  -X    Enable debug logging
  -endpoint string
        Endpoint to inspect SSL on. Can be https://domain (assuming port 443) or a domain and port after a colon (:)
  -trustStore string
        Path to an optional JKS trust store
  -trustStorePassphrase string
        Passphrase for optional JKS trust store
```

Example for a known expired certificate at the endpoint:

```
./ssl-inspector -endpoint expired.badssl.com:443

 ____  ____  _       _  _      ____  ____  _____ ____  _____  ____  ____
/ ___\/ ___\/ \     / \/ \  /|/ ___\/  __\/  __//   _\/__ __\/  _ \/  __\
|    \|    \| |     | || |\ |||    \|  \/||  \  |  /    / \  | / \||  \/|
\___ |\___ || |_/\  | || | \||\___ ||  __/|  /_ |  \__  | |  | \_/||    /
\____/\____/\____/  \_/\_/  \|\____/\_/   \____\\____/  \_/  \____/\_/\_\


Running on:             darwin/arm64
Version:                development

Validated - conducting test against: expired.badssl.com:443

❌ Connection to expired.badssl.com:443 will not work.

There are 1 certificate errors connecting to expired.badssl.com:443. They are:

 [1] - Certifcate for CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard is invalid because: Certificate expired

```

Example for a known certificate that is signed by a CA that is not trusted:

```
./ssl-inspector -endpoint untrusted-root.badssl.com:443


 ____  ____  _       _  _      ____  ____  _____ ____  _____  ____  ____
/ ___\/ ___\/ \     / \/ \  /|/ ___\/  __\/  __//   _\/__ __\/  _ \/  __\
|    \|    \| |     | || |\ |||    \|  \/||  \  |  /    / \  | / \||  \/|
\___ |\___ || |_/\  | || | \||\___ ||  __/|  /_ |  \__  | |  | \_/||    /
\____/\____/\____/  \_/\_/  \|\____/\_/   \____\\____/  \_/  \____/\_/\_\


Running on:             darwin/arm64
Version:                development

Validated - conducting test against: untrusted-root.badssl.com:443

❌ Connection to untrusted-root.badssl.com:443 will not work.

There are 1 certificate errors connecting to untrusted-root.badssl.com:443. They are:

 [1] - Certifcate for CN=*.badssl.com,O=BadSSL,L=San Francisco,ST=California,C=US is not trusted. This could be because:
        1. It is self-signed
        2. It is signed by an unknown authority
        3. The CA that signed this certificate is not a invalid Certificate Authority

        It was signed by: BadSSL Untrusted Root Certificate Authority

```

Example for a known certificate that is signed by a CA that is included in the supplied trust store:

```
./ssl-inspector -endpoint untrusted-root.badssl.com:443 -trustStore ./test-data/test-keystore.jks -trustStorePassphrase changeit


 ____  ____  _       _  _      ____  ____  _____ ____  _____  ____  ____
/ ___\/ ___\/ \     / \/ \  /|/ ___\/  __\/  __//   _\/__ __\/  _ \/  __\
|    \|    \| |     | || |\ |||    \|  \/||  \  |  /    / \  | / \||  \/|
\___ |\___ || |_/\  | || | \||\___ ||  __/|  /_ |  \__  | |  | \_/||    /
\____/\____/\____/  \_/\_/  \|\____/\_/   \____\\____/  \_/  \____/\_/\_\


Running on:             darwin/arm64
Version:                development

Validated - conducting test against: untrusted-root.badssl.com:443

- Loaded Custom CA: BadSSL Untrusted Root Certificate Authority


✅ All checked passed connecting to untrusted-root.badssl.com:443

```

## Testing with a custom Trust Store

A custom Java Keystore (JKS) can be used to provide additional trusted certificate authorities that may not be in the Operating System trust store.

1. Obtain the Certifcate for the CA you wish to trust (in PEM format) - try `https://untrusted-root.badssl.com` as a good example!
2. Load into a JKS:
    ```
    keytool -importcert -storetype jks -file my-ca.pem -alias BadSSLCA -storepass changeit -keystore test-keystore.jks
    ```

## The Fine Print

Remember:

This project is part of the [Sonatype Nexus Community](https://github.com/sonatype-nexus-community) organization, which is not officially supported by Sonatype. Please review the latest pull requests, issues, and commits to understand this project's readiness for contribution and use.

-   File suggestions and requests on this repo through GitHub Issues, so that the community can pitch in
-   Use or contribute to this project according to your organization's policies and your own risk tolerance
-   Don't file Sonatype support tickets related to this project— it won't reach the right people that way

Last but not least of all - have fun!

<!-- Links Section -->

[shield_gh-workflow-test]: https://img.shields.io/github/actions/workflow/status/sonatype-nexus-community/ssl-inspector/build.yaml?branch=main&logo=GitHub&logoColor=white 'build'
[shield_license]: https://img.shields.io/github/license/sonatype-nexus-community/ssl-inspector?logo=open%20source%20initiative&logoColor=white 'license'
[link_gh-workflow-test]: https://github.com/sonatype-nexus-community/ssl-inspector/actions/workflows/build.yaml?query=branch%3Amain
[license_file]: https://github.com/sonatype-nexus-community/ssl-inspector/blob/main/LICENSE
