DeepViolet
==========

Java GUI tool for introspection of SSL\TLS sessions.  Inspired by work by Qualys SSL Labs and Ivan Ristić.  I have also tried to include some attribution where it's deserved at least in the code comments for now.  Original blog article post describing this project, http://www.securitycurmudgeon.com/2014/07/ssltls-introspection.html

This program is provided for educational purposes.  Use at your own risk.  This program is only available in US English.

Sample Output from GUI tool (anonymized)

--------------------------------------------

--------------------------------------------

[Report Run Information]
DeepViolet V0.1
Report generated on Mon Jul 21 23:39:58 PDT 2014
Target url https://www.foo.com

[Host information]
host=www.foo.com [192.168.1.146], canonical=hkg03s13-in-f18.foo.com
host=www.foo.com [192.168.1.145], canonical=hkg03s13-in-f17.foo.com
host=www.foo.com [192.168.1.144], canonical=hkg03s13-in-f16.foo.com
host=www.foo.com [192.168.1.147], canonical=hkg03s13-in-f19.foo.com
host=www.foo.com [192.168.1.148], canonical=hkg03s13-in-f20.foo.com
host=www.foo.com [1111:1111:1111:1111:1111:0:0:1111], canonical=hkg03s11-in-x11.foo.com

[Connection characteristics]
SO_KEEPALIVE=false
SO_RECBUF=131874
SO_LINGER=-1
SO_TIMEOUT=0
Traffic Class=0
Client Auth Required=false
SO_REUSEADDR=false
TCP_NODELAY=false

[Host supported server cipher suites]
SSLv3
TLS1.0
TLS1.1
TLS1.2
  - (SUPPORTED) TLS_RSA_WITH_AES_128_CBC_SHA (STRENGTH=STRONG )
Uncategorized
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (STRENGTH=STRONG )
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (STRENGTH=STRONG )
  - (SUPPORTED) TLS_RSA_WITH_AES_128_CBC_SHA (STRENGTH=STRONG )
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_RC4_128_SHA (STRENGTH=STRONG )
  - (SUPPORTED) SSL_RSA_WITH_RC4_128_SHA (STRENGTH=STRONG )
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (STRENGTH=STRONG )
  - (SUPPORTED) TLS_RSA_WITH_AES_128_GCM_SHA256 (STRENGTH=STRONG )
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (STRENGTH=STRONG )
  - (SUPPORTED) SSL_RSA_WITH_3DES_EDE_CBC_SHA (STRENGTH=STRONG )
  - (SUPPORTED) SSL_RSA_WITH_RC4_128_MD5 (STRENGTH=STRONG )

[Server certificate information]
Trusted Status=TRUSTED
Validity Status= VALID.  Certificate valid between Wed Jul 02 06:38:55 PDT 2014 and Mon Sep 29 17:00:00 PDT 2014
SubjectDN=CN=www.foo.com, O=Shmo Inc, L=San Jose, ST=California, C=US
IssuerDN=CN=Joe Shmo CA, O=Shmo Inc, C=US
Serial Number=6593427055677612812
Signature Algorithm=SHA1withRSA
Signature Algorithm OID=1.2.840.113549.1.1.5
Certificate Version =3
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06

[Server certificate chain]
Chain summary
|
|
End-Enity Certificate--->CN=www.foo.com, O=Shmo Inc, L=San Jose, ST=California, C=US
   |
   |
   Intermediate CA--->CN=Joe Shmo CA, O=Shmo Inc, C=US
      |
      |
      Intermediate CA--->CN=Super Global CA CA, O=Super Global Inc., C=US
            |
            |
            Root CA(Java CACERTS)--->OU=Centrex Secure Certificate Authority, O=Centrex, C=US

Chain details
Validity Status= VALID.  Certificate valid between Wed Jul 02 06:38:55 PDT 2014 and Mon Sep 29 17:00:00 PDT 2014
SubjectDN=CN=www.foo.com, O=Shmo Inc, L=San Jose, ST=California, C=US
IssuerDN=CN=Joe Shmo CA, O=Shmo Inc, C=US
Serial Number=6593427055677612812
Signature Algorithm=SHA1withRSA
Signature Algorithm OID=1.2.840.113549.1.1.5
Certificate Version =3
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06

Validity Status= VALID.  Certificate valid between Fri Apr 05 08:15:55 PDT 2013 and Sat Apr 04 08:15:55 PDT 2015
SubjectDN=CN=Joe Shmo CA, O=Shmo Inc, C=US
IssuerDN=CN=Super Global CA, O=Super Global Inc., C=US
Serial Number=146345
Signature Algorithm=SHA1withRSA
Signature Algorithm OID=1.2.840.113549.1.1.5
Certificate Version =3
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06

Validity Status= VALID.  Certificate valid between Mon May 20 21:00:00 PDT 2002 and Mon Aug 20 21:00:00 PDT 2018
SubjectDN=CN=Super Global CA, O=Super Global Inc., C=US
IssuerDN=CN=Super Global CA, O=Super Global Inc., C=US
Serial Number=123458643
Signature Algorithm=SHA1withRSA
Signature Algorithm OID=1.2.840.113549.1.1.5
Certificate Version =3
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06

--------------------------------------------

--------------------------------------------


INSTALL AND RUN

1) Git the code

2) Edit logging properties in logback.xml as desired.  Currently a debug file is created in /Users/milton/DeepViolet/DeepVioletLog.txt.  You will want to update for your system with an appropriate fully qualified file name.  This file contains diagnostic output, program errors, exceptional conditions, etc.

3) Report folder.  This output is identical to the output printed to the screen and is useful to when referring to previous runs.  When the tool is run it writes a copy of the completed report to,
~/DeepViolet/ (Mac OS X & *NIX )
C:\My Documents\DeepViolet\ (Windows, not tested)
Reports files are written in the following format,
DeepViolet-<host>-yyyy-mm-dd-hr-mm-sec-tz.txt  

4) Permissions.  Make sure the account assigned to process has full privileges to the previously mentioned directories.
