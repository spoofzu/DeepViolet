DeepViolet<br/>
==========<br/>
<br/>
Java GUI tool for introspection of SSL\TLS sessions.  Inspired from work by Qualys SSL Labs and Ivan Ristić.  I have also tried to include some attribution where it's deserved at least in the code comments for now.  Original blog article post describing this project, http://www.securitycurmudgeon.com/2014/07/ssltls-introspection.html<br/>
<br/>
This program is provided for educational purposes.  Use at your own risk.  This program is only available in US English.<br/>
<br/>
Sample Output from GUI tool (anonymized)<br/>
--------------------------------------------<br/>
<br/>
[Report Run Information]<br/>
DeepViolet V0.1<br/>
Report generated on Mon Jul 21 23:39:58 PDT 2014<br/>
Target url https://www.foo.com<br/>
<br/>
[Host information]<br/>
host=www.foo.com [192.168.1.146], canonical=hkg03s13-in-f18.foo.com<br/>
host=www.foo.com [192.168.1.145], canonical=hkg03s13-in-f17.foo.com<br/>
host=www.foo.com [192.168.1.144], canonical=hkg03s13-in-f16.foo.com<br/>
host=www.foo.com [192.168.1.147], canonical=hkg03s13-in-f19.foo.com<br/>
host=www.foo.com [192.168.1.148], canonical=hkg03s13-in-f20.foo.com<br/>
host=www.foo.com [1111:1111:1111:1111:1111:0:0:1111], canonical=hkg03s11-in-x11.foo.com<br/>
<br/>
[Connection characteristics]<br/>
SO_KEEPALIVE=false<br/>
SO_RECBUF=131874<br/>
SO_LINGER=-1<br/>
SO_TIMEOUT=0<br/>
Traffic Class=0<br/>
Client Auth Required=false<br/>
SO_REUSEADDR=false<br/>
TCP_NODELAY=false<br/>
<br/>
[Host supported server cipher suites]<br/>
SSLv3<br/>
TLS1.0<br/>
TLS1.1<br/>
TLS1.2<br/>
  - (SUPPORTED) TLS_RSA_WITH_AES_128_CBC_SHA (STRENGTH=STRONG )<br/>
Uncategorized<br/>
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (STRENGTH=STRONG )<br/>
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (STRENGTH=STRONG )<br/>
  - (SUPPORTED) TLS_RSA_WITH_AES_128_CBC_SHA (STRENGTH=STRONG )<br/>
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_RC4_128_SHA (STRENGTH=STRONG )<br/>
  - (SUPPORTED) SSL_RSA_WITH_RC4_128_SHA (STRENGTH=STRONG )<br/>
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (STRENGTH=STRONG )<br/>
  - (SUPPORTED) TLS_RSA_WITH_AES_128_GCM_SHA256 (STRENGTH=STRONG )<br/>
  - (SUPPORTED) TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (STRENGTH=STRONG )<br/>
  - (SUPPORTED) SSL_RSA_WITH_3DES_EDE_CBC_SHA (STRENGTH=STRONG )<br/>
  - (SUPPORTED) SSL_RSA_WITH_RC4_128_MD5 (STRENGTH=STRONG )<br/>
<br/>
[Server certificate information]<br/>
Trusted Status=TRUSTED<br/>
Validity Status= VALID.  Certificate valid between Wed Jul 02 06:38:55 PDT 2014 and Mon Sep 29 17:00:00 PDT 2014<br/>
SubjectDN=CN=www.foo.com, O=Shmo Inc, L=San Jose, ST=California, C=US<br/>
IssuerDN=CN=Joe Shmo CA, O=Shmo Inc, C=US<br/>
Serial Number=6593427055677612812<br/>
Signature Algorithm=SHA1withRSA<br/>
Signature Algorithm OID=1.2.840.113549.1.1.5<br/>
Certificate Version =3<br/>
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD<br/>
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06<br/>
<br/>
[Server certificate chain]<br/>
Chain summary<br/>
|<br/>
|<br/>
End-Enity Certificate--->CN=www.foo.com, O=Shmo Inc, L=San Jose, ST=California, C=US<br/>
&nbsp;&nbsp;|<br/>
&nbsp;&nbsp;|<br/>
&nbsp;&nbsp;Intermediate CA--->CN=Joe Shmo CA, O=Shmo Inc, C=US<br/>
&nbsp;&nbsp;&nbsp;&nbsp;|<br/>
&nbsp;&nbsp;&nbsp;&nbsp;|<br/>
&nbsp;&nbsp;&nbsp;&nbsp;Intermediate CA--->CN=Super Global CA CA, O=Super Global Inc., C=US<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;|<br/>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Root CA(Java CACERTS)--->OU=Centrex Secure Certificate Authority, O=Centrex, C=US<br/>
<br/>
Chain details<br/>
Validity Status= VALID.  Certificate valid between Wed Jul 02 06:38:55 PDT 2014 and Mon Sep 29 17:00:00 PDT 2014<br/>
SubjectDN=CN=www.foo.com, O=Shmo Inc, L=San Jose, ST=California, C=US<br/>
IssuerDN=CN=Joe Shmo CA, O=Shmo Inc, C=US<br/>
Serial Number=6593427055677612812<br/>
Signature Algorithm=SHA1withRSA<br/>
Signature Algorithm OID=1.2.840.113549.1.1.5<br/>
Certificate Version =3<br/>
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD<br/>
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06<br/>
<br/>
Validity Status= VALID.  Certificate valid between Fri Apr 05 08:15:55 PDT 2013 and Sat Apr 04 08:15:55 PDT 2015<br/>
SubjectDN=CN=Joe Shmo CA, O=Shmo Inc, C=US<br/>
IssuerDN=CN=Super Global CA, O=Super Global Inc., C=US<br/>
Serial Number=146345<br/>
Signature Algorithm=SHA1withRSA<br/>
Signature Algorithm OID=1.2.840.113549.1.1.5<br/>
Certificate Version =3<br/>
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD<br/>
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06<br/>
<br/>
Validity Status= VALID.  Certificate valid between Mon May 20 21:00:00 PDT 2002 and Mon Aug 20 21:00:00 PDT 2018<br/>
SubjectDN=CN=Super Global CA, O=Super Global Inc., C=US<br/>
IssuerDN=CN=Super Global CA, O=Super Global Inc., C=US<br/>
Serial Number=123458643<br/>
Signature Algorithm=SHA1withRSA<br/>
Signature Algorithm OID=1.2.840.113549.1.1.5<br/>
Certificate Version =3<br/>
SHA1 Fingerprint=0x91:04:06:02:F5:74:20:7B:CC:26:DF:31:B3:3A:D8:CB:77:37:1B:DD<br/>
MD5 Fingerprint=0x48:A5:56:5C:CC:11:55:CA:1A:55:A0:3C:C6:23:D6:06<br/>
<br/>
--------------------------------------------<br/>
<br/>
INSTALL AND RUN<br/>
<br/>
1) Git the code<br/>
<br/>
2) Edit logging properties in logback.xml as desired.  Currently a debug file is created in /Users/milton/DeepViolet/DeepVioletLog.txt.  You will want to update for your system with an appropriate fully qualified file name.  This file contains diagnostic output, program errors, exceptional conditions, etc.<br/>
<br/>
3) Report folder.  This output is identical to the output printed to the screen and is useful to when referring to previous runs.  When the tool is run it writes a copy of the completed report to,<br/>
~/DeepViolet/ (Mac OS X & *NIX )<br/>
C:\My Documents\DeepViolet\ (Windows, not tested)<br/>
Reports files are written in the following format,<br/>
DeepViolet-<host>-yyyy-mm-dd-hr-mm-sec-tz.txt  <br/>
<br/>
4) Permissions.  Make sure the account assigned to process has full privileges to the previously mentioned directories.
<br/>
