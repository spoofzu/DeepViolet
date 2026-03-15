[![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/europe/2016.svg)](http://www.blackhat.com/eu-16/arsenal.html#milton-smith)
[![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/usa/2018.svg)](https://www.blackhat.com/us-18/arsenal/schedule/index.html#deepviolet-ssltls-scanning-api-38-tools-10724)

# DeepViolet TLS/SSL API

[Documentation](docs/DeepViolet.md) |
[API JavaDoc](docs/javadocs/index.html) |
[Changes from Upstream](docs/CHANGES.md) |
[Reference Tools](https://github.com/spoofzu/DeepVioletTools)

DeepViolet is a TLS/SSL scanning API written in Java. It provides programmatic introspection of TLS/SSL connections, including certificate chain analysis, cipher suite enumeration, risk scoring, TLS fingerprinting, DNS security checks (CAA, DANE/TLSA), certificate revocation verification (OCSP, CRL, CT), and support for multiple naming conventions (IANA, OpenSSL, GnuTLS, NSS). Protocols SSLv2 through TLS 1.3 are supported. Multi-host scanning with configurable concurrency, cooperative pause/cancel, event-driven monitoring, and flexible target parsing (hostnames, IPs, CIDR, IP ranges) are also available.

GUI and command-line reference tools that consume this API are available in the [DeepVioletTools](https://github.com/spoofzu/DeepVioletTools) project.

## Requirements

- Java 21 or higher
- Apache Maven 3.6.3 or higher

## Quick Start

```bash
mvn clean verify
```

## Using in Your Project

DeepViolet is available on [Maven Central](https://central.sonatype.com/). Add it to your `pom.xml`:

```xml
<dependency>
    <groupId>com.github.spoofzu</groupId>
    <artifactId>DeepViolet</artifactId>
    <version>5.2.0</version>
</dependency>
```

## Documentation

See [docs/DeepViolet.md](docs/DeepViolet.md) for architecture, features, building, API usage, and contributing guidelines.

## Project History

DeepViolet was previously an OWASP project but is no longer affiliated with OWASP.

## Acknowledgements

This tool implements ideas, code, and takes inspiration from other projects and leaders like: Qualys SSL Labs, Ivan Ristic, OpenSSL, and Oracle's Java Security Team. Original default cipher suite meta was are derived from [Mozilla Server Side TLS v5.7](https://ssl-config.mozilla.org/guidelines/5.7.json) guidelines. TLS/SSL raw socket adapted from code examples by Thomas Pornin. Significant development contributions by [Claude Code](https://claude.ai/code) from Anthropic.

## License

[Apache License, Version 2.0](LICENSE)

*This project leverages the works of other open source community projects and is provided for educational purposes. Use at your own risk.*

## Disclaimer

The author is an employee of Oracle Corporation. This project is a personal endeavor and is not affiliated with, sponsored by, or endorsed by Oracle. All views and code are the author's own.
