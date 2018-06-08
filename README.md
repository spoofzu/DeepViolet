[![Build Status](https://travis-ci.org/spoofzu/DeepViolet.svg?branch=master)](https://travis-ci.org/spoofzu/DeepViolet)
[![Black Hat Arsenal](https://www.toolswatch.org/badges/arsenal/2016.svg)](http://www.blackhat.com/eu-16/arsenal.html#milton-smith)

# OWASP DeepViolet TLS/SSL API

[WIKI/How to Build](https://github.com/spoofzu/DeepViolet/wiki/Build-on-Your-Computer) | 
[API JavaDocs](https://spoofzu.github.io/DeepViolet/) | 
[OWASP Project Page](https://www.owasp.org/index.php/OWASP_DeepViolet_TLS/SSL_Scanner) | 
[Reference Screenshots](https://github.com/spoofzu/DeepViolet/wiki/Running-Reference-Tools)

DeepViolet is a TLS/SSL scanning API written in Java. To keep DeepViolet easy to use, identify bugs, reference implementations have been developed that consume the API. If you want to see what DeepViolet can do, use it from the command line in your scripts or use the graphical tool from the comfort of your desktop. Both tools can be used to scan HTTPS web servers to check server certificate trust chains, revocation status, check certificates for pending expiration, weak signing algorithms and much more.  Original blog article post describing this project, http://www.securitycurmudgeon.com/2014/07/ssltls-introspection.html

## Benefits

Use X.509 certificate metadata in creative ways.  Extend security tooling to include TLS analysis.  See the [project wiki](https://github.com/spoofzu/DeepViolet/wiki/Features) 

## How do I include DeepViolet API in my projects?

DeepViolet is deployed in Maven Central repository.  Include the following dependency in your pom.xml,

```xml
<dependency>
  <groupId>com.github.spoofzu</groupId>
  <artifactId>DeepViolet</artifactId>
  <version>5.1.1-SNAPSHOT</version>
</dependency>
```

## Acknowledgements

This tool implements ideas, code, and takes inspiration from other projects and leaders like: Qualys SSL Labs and Ivan Ristić, OpenSSL, and Oracle's Java Security Team.  Many thanks for around negotiating TLS/SSL handshakes and cipher suite handling adapted from code examples by Thomas Pornin.

## More Information?

See the [project wiki](https://github.com/spoofzu/DeepViolet/wiki) 

<i>This project leverages the works of other open source community projects and is provided for educational purposes.  Use at your own risk.  See [LICENSE](https://github.com/spoofzu/DeepViolet/blob/master/LICENSE) for further information.</i>
