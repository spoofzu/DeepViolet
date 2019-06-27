[![Build Status](https://travis-ci.org/spoofzu/DeepViolet.svg?branch=master)](https://travis-ci.org/spoofzu/DeepViolet)
[![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/europe/2016.svg)](http://www.blackhat.com/eu-16/arsenal.html#milton-smith)
[![Black Hat Arsenal](https://github.com/toolswatch/badges/blob/master/arsenal/usa/2018.svg)](https://www.blackhat.com/us-18/arsenal/schedule/index.html#deepviolet-ssltls-scanning-api-38-tools-10724)

*********************************************************************
THIS PROJECT IS ON HOLD AND NOT BEING MAINTAINED.  I DON'T
RECOMMEND YOU USE THIS CODE FOR ANYTHING IMPORTANT. I'M KEEPING THE 
REPO AVAILABLE FOR THOESE INTERESTED IN THE CODE.  THE PROJECT WAS
A FUN EXPERIMENT AND IT WAS EXCITING TO SHARE IT
WITH EVERYONE.  HOWEVER, AT THIS TIME, I'M PLACING MY TIME AND
ENERGY INTO OTHER AREAS.  JUN 27, 2019 --MILTON                                             
*********************************************************************

# OWASP DeepViolet TLS/SSL API

[OWASP Project Page](https://www.owasp.org/index.php/OWASP_DeepViolet_TLS/SSL_Scanner) | 
[WIKI](https://github.com/spoofzu/DeepViolet/wiki/Build-on-Your-Computer) | 
[Reference Tools](https://github.com/spoofzu/DeepVioletTools)

DeepViolet is a TLS/SSL scanning API written in Java. To keep DeepViolet easy to use, identify bugs, reference implementations have been developed that consume the API. If you want to see what DeepViolet can do, use it from the command line in your scripts or use the graphical tool from the comfort of your desktop. Both tools can be used to scan HTTPS web servers to check server certificate trust chains, revocation status, check certificates for pending expiration, weak signing algorithms and much more.  Original blog article post describing this project, http://www.securitycurmudgeon.com/2014/07/ssltls-introspection.html

## Benefits

Use X.509 certificate metadata in creative ways.  Extend security tooling to include TLS analysis.  See the [project wiki](https://github.com/spoofzu/DeepViolet/wiki/Features) 

## How do I include DeepViolet API in my projects?

DeepViolet is deployed in Maven Central repository.  Include the following DeepViolet release dependency in your pom.xml,

```xml
<dependency>
  <groupId>com.github.spoofzu</groupId>
  <artifactId>DeepViolet</artifactId>
  <version>5.1.16</version>
</dependency>
```

Alternatively, include the latest development build which will someday become the next release build.

```xml
<dependency>
  <groupId>com.github.spoofzu</groupId>
  <artifactId>DeepViolet</artifactId>
  <version>5.1.17-SNAPSHOT</version>
</dependency>
```

## More Information?

See the [project wiki](https://github.com/spoofzu/DeepViolet/wiki) 

<i>This project leverages the works of other open source community projects and is provided for educational purposes.  Use at your own risk.  See [LICENSE](https://github.com/spoofzu/DeepViolet/blob/master/LICENSE) for further information.</i>

## Acknowledgements

This tool implements ideas, code, and takes inspiration from other projects and leaders like: Qualys SSL Labs and Ivan Ristić, OpenSSL, and Oracle's Java Security Team.  Many thanks negotiating TLS/SSL handshakes and ciphersuite handling adapted from code examples by Thomas Pornin.
