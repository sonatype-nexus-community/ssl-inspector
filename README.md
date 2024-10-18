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

```
./ssl-inspector --help
```

```
./ssl-inspector -endpoint expired.badssl.com:443
```

## The Fine Print

Remember:

This project is part of the [Sonatype Nexus Community](https://github.com/sonatype-nexus-community) organization, which is not officially supported by Sonatype. Please review the latest pull requests, issues, and commits to understand this project's readiness for contribution and use.

-   File suggestions and requests on this repo through GitHub Issues, so that the community can pitch in
-   Use or contribute to this project according to your organization's policies and your own risk tolerance
-   Don't file Sonatype support tickets related to this project— it won't reach the right people that way

Last but not least of all - have fun!

<!-- Links Section -->

[shield_gh-workflow-test]: https://img.shields.io/github/actions/workflow/status/sonatype-nexus-community/ssl-inspector/release.yaml?branch=main&logo=GitHub&logoColor=white 'build'
[shield_license]: https://img.shields.io/github/license/sonatype-nexus-community/ssl-inspector?logo=open%20source%20initiative&logoColor=white 'license'
[link_gh-workflow-test]: https://github.com/sonatype-nexus-community/ssl-inspector/actions/workflows/release.yaml?query=branch%3Amain
[license_file]: https://github.com/sonatype-nexus-community/ssl-inspector/blob/main/LICENSE
