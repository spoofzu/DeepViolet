DeepViolet<br/>
==========<br/>
<br/>
Java GUI tool for introspection of SSL\TLS sessions.  Inspired from work by Qualys SSL Labs and Ivan Ristić.  I have also tried to include some attribution where it's deserved at least in the code comments for now.  Original blog article post describing this project, http://www.securitycurmudgeon.com/2014/07/ssltls-introspection.html<br/>
<p/>
TRY NOW, 1) make sure Java 8 installed, 2) download dvUI.jar to your desktop and double-click to run, 3) alternatively, download dvCMD.jar and run in your shell scripts.  See <a href=http://www.securitycurmudgeon.com/2015/02/deepviolet-improvements-for-feb-2015.html>DeepViolet Improvements for Feb 2015</a> for more details.
<p/>
This program is provided for educational purposes.  Use at your own risk.  This program is only available in US English.<br/>
<br/>
Sample Output from GUI tool (anonymized)<br/>
--------------------------------------------<br/>
<br/>
<code>
	
	[Report run information]
	DeepViolet V0.2
	Report generated on Fri Nov 21 16:09:09 PST 2014
	Target url https://www.company.com/

	[Host information]
	host=www.company.com [192.168.2.40], canonical=192.168.2.40
	host=www.company.com [192.168.2.39], canonical=192.168.2.39

	[HTTP(S) response headers]
	<null> : HTTP/1.1 200 OK
	Cache-Control : no-cache
	Etag : "d96a82aa2cf7938c128047c07723239926e6091a"
	Server : nginx
	Connection : keep-alive
	Set-Cookie : _xsrf=7a11255d19254540a9ae32d66814d585; Path=/; secure
	Last-Modified : Thu, 20 Nov 2014 21:30:37 GMT
	P3P : CP="CAO PSA OUR"
	Content-Length : 125273
	Date : Sat, 22 Nov 2014 00:09:11 GMT
	Content-Type : text/html; charset=utf-8

	[Connection characteristics]
	SO_KEEPALIVE=false
	SO_RECBUF=131400
	SO_LINGER=-1
	SO_TIMEOUT=0
	Traffic Class=0
	Client Auth Required=false
	SO_REUSEADDR=false
	TCP_NODELAY=false

	[Host supported server cipher suites]
	SSLv3
	 - RSA_WITH_RC4_128_SHA(0x5) (STRONG)
	 - RSA_WITH_IDEA_CBC_SHA(0x7) (STRONG)
	 - RSA_WITH_AES_128_CBC_SHA(0x2f) (STRONG)
	 - RSA_WITH_AES_256_CBC_SHA(0x35) (STRONG)
	 - RSA_WITH_CAMELLIA_128_CBC_SHA(0x41) (STRONG)
	 - RSA_WITH_CAMELLIA_256_CBC_SHA(0x84) (STRONG)
	 - TLS_RSA_WITH_SEED_CBC_SHA(0x96) (STRONG)
	 - TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xc011) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014) (STRONG)
	 - TLS_ECDH_anon_WITH_RC4_128_SHA(0xc016) (STRONG)
	 - TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xc018) (STRONG)
	 - TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xc019) (STRONG)
	TLSv1.2
	 - RSA_WITH_RC4_128_SHA(0x5) (STRONG)
	 - RSA_WITH_IDEA_CBC_SHA(0x7) (STRONG)
	 - RSA_WITH_AES_128_CBC_SHA(0x2f) (STRONG)
	 - RSA_WITH_AES_256_CBC_SHA(0x35) (STRONG)
	 - RSA_WITH_AES_128_CBC_SHA256(0x3c) (STRONG)
	 - RSA_WITH_AES_256_CBC_SHA256(0x3d) (STRONG)
	 - RSA_WITH_CAMELLIA_128_CBC_SHA(0x41) (STRONG)
	 - RSA_WITH_CAMELLIA_256_CBC_SHA(0x84) (STRONG)
	 - TLS_RSA_WITH_SEED_CBC_SHA(0x96) (STRONG)
	 - TLS_RSA_WITH_AES_128_GCM_SHA256(0x9c) (STRONG)
	 - TLS_RSA_WITH_AES_256_GCM_SHA384(0x9d) (STRONG)
	 - TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xc011) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014) (STRONG)
	 - TLS_ECDH_anon_WITH_RC4_128_SHA(0xc016) (STRONG)
	 - TLS_ECDH_anon_WITH_AES_128_CBC_SHA(0xc018) (STRONG)
	 - TLS_ECDH_anon_WITH_AES_256_CBC_SHA(0xc019) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xc027) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xc028) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xc02f) (STRONG)
	 - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xc030) (STRONG)
	TLSv1.1
	 - No Ciphers ()
	TLSv1.0
	 - No Ciphers ()

	[Server certificate information]
	Trusted Status=TRUSTED
	Validity Status= VALID.  Certificate valid between Mon Mar 18 17:00:00 PDT 2013 and Thu May 21 05:00:00 PDT 2015
	SubjectDN=CN=www.company.com, OU=Operations, O="company, Inc.", L=New York, ST=New York, C=US
	IssuerDN=CN=DigiCert High Assurance CA-3, OU=www.digicert.com, O=DigiCert Inc, C=US
	Serial Number=17294881921818988019291918345699297521
	Signature Algorithm=SHA1withRSA
	Signature Algorithm OID=1.2.840.113549.1.1.5
	Certificate Version =3
	SHA1 Fingerprint=0x81:23:3F:98:93:0D:4E:B4:C9:38:D1:8D:E0:18:12:E5:01:A1:51:40
	MD5 Fingerprint=0xEE:63:BE:4B:8E:57:8A:12:17:22:33:62:EE:78:6E:E6
	Non-critical OIDs
	  -AuthorityInfoAccess(1.3.6.1.5.5.7.1.1) = [ocsp=http://ocsp.digicert.com | caIssuers=http://cacerts.digicert.com/DigiCertHighAssuranceCA-3.crt ]
	  -SubjectKeyIdentifier(2.5.29.14) = <UNSUPPORTED>
	  -SubjectAlternativeName(2.5.29.17) = [www.company.com | www.www.company.com ]
	  -CRLDistributionPoints(2.5.29.31) = [http://crl3.digicert.com/ca9-g00.crl | http://crl4.digicert.com/ca9-g22.crl ]
	  -CertificatePolicies(2.5.29.32) = [2.16.840.1.114412.1.1=qualifierID=https://www.digicert.com/CPS ]
	  -AuthorityKeyIdentifier(2.5.29.35) = <UNSUPPORTED>
	  -ExtendedKeyUsages(2.5.29.37) = [serverauth clientauth ]
	Critical OIDs
	  -KeyUsage(2.5.29.15) = [keycertsign ]
	  -BasicConstraints(2.5.29.19) = []

	[Server certificate chain]
	Chain Summary, leaf --> root
	|
	|
	End-Entity Certificate--->CN=www.company.com, OU=Operations, O="company, Inc.", L=New York, ST=New York, C=US
	   |
	   |
	   Intermediate CA--->CN=DigiCert High Assurance CA-3, OU=www.digicert.com, O=DigiCert Inc, C=US
	      |
	      |
	      Self-Signed Root--->CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US

	[Chain details]
	Validity Status= VALID.  Certificate valid between Mon Mar 18 17:00:00 PDT 2013 and Thu May 21 05:00:00 PDT 2015
	SubjectDN=CN=www.company.com, OU=Operations, O="company, Inc.", L=New York, ST=New York, C=US
	IssuerDN=CN=DigiCert High Assurance CA-3, OU=www.digicert.com, O=DigiCert Inc, C=US
	Serial Number=17294881921818988019291918345699297521
	Signature Algorithm=SHA1withRSA
	Signature Algorithm OID=1.2.840.113549.1.1.5
	Certificate Version =3
	SHA1 Fingerprint=0x81:23:3F:98:93:0D:4E:B4:C9:38:D1:8D:E0:18:12:E5:01:A1:51:40
	MD5 Fingerprint=0xEE:63:BE:4B:8E:57:8A:12:17:22:33:62:EE:78:6E:E6
	Non-critical OIDs
	  -AuthorityInfoAccess(1.3.6.1.5.5.7.1.1) = [ocsp=http://ocsp.digicert.com | caIssuers=http://cacerts.digicert.com/DigiCertHighAssuranceCA-3.crt ]
	  -SubjectKeyIdentifier(2.5.29.14) = <UNSUPPORTED>
	  -SubjectAlternativeName(2.5.29.17) = [www.company.com | www.company.com ]
	  -CRLDistributionPoints(2.5.29.31) = [http://crl3.digicert.com/ca9-g00.crl | http://crl4.digicert.com/ca9-g22.crl ]
	  -CertificatePolicies(2.5.29.32) = [2.16.840.1.114412.1.1=qualifierID=https://www.digicert.com/CPS ]
	  -AuthorityKeyIdentifier(2.5.29.35) = <UNSUPPORTED>
	  -ExtendedKeyUsages(2.5.29.37) = [serverauth clientauth ]
	Critical OIDs
	  -KeyUsage(2.5.29.15) = [keycertsign ]
	  -BasicConstraints(2.5.29.19) = []

	Validity Status= VALID.  Certificate valid between Wed Apr 02 05:00:00 PDT 2008 and Sat Apr 02 17:00:00 PDT 2022
	SubjectDN=CN=DigiCert High Assurance CA-3, OU=www.digicert.com, O=DigiCert Inc, C=US
	IssuerDN=CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
	Serial Number=13785899061980321600472330812886105915
	Signature Algorithm=SHA1withRSA
	Signature Algorithm OID=1.2.840.113549.1.1.5
	Certificate Version =3
	SHA1 Fingerprint=0x42:85:78:55:FB:0E:A4:3F:54:C9:91:1E:30:E7:79:1D:8C:E8:27:05
	MD5 Fingerprint=0xC6:8B:99:30:C8:57:8D:41:6F:8C:09:4E:6A:DB:0C:90
	Non-critical OIDs
	  -AuthorityInfoAccess(1.3.6.1.5.5.7.1.1) = [ocsp=http://ocsp.digicert.com ]
	  -SubjectKeyIdentifier(2.5.29.14) = <UNSUPPORTED>
	  -CRLDistributionPoints(2.5.29.31) = [http://crl3.digicert.com/DigiCertHighAssuranceEVRootCA.crl | http://crl4.digicert.com/DigiCertHighAssuranceEVRootCA.crl ]
	  -CertificatePolicies(2.5.29.32) = [2.16.840.1.114412.1.3.0.2=qualifierID=http://www.digicert.com/ssl-cps-repository.htm 1.3.6.1.5.5.7.2.2=Unhandled type, see log ]
	  -AuthorityKeyIdentifier(2.5.29.35) = <UNSUPPORTED>
	Critical OIDs
	  -KeyUsage(2.5.29.15) = [nonrepudiation keyencipherment ]
	  -BasicConstraints(2.5.29.19) = [TRUE 0 ]

	Validity Status= VALID.  Certificate valid between Thu Nov 09 16:00:00 PST 2006 and Sun Nov 09 16:00:00 PST 2031
	SubjectDN=CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
	IssuerDN=CN=DigiCert High Assurance EV Root CA, OU=www.digicert.com, O=DigiCert Inc, C=US
	Serial Number=3553400076410547919724730734378100087
	Signature Algorithm=SHA1withRSA
	Signature Algorithm OID=1.2.840.113549.1.1.5
	Certificate Version =3
	SHA1 Fingerprint=0x5F:B7:EE:06:33:E2:59:DB:AD:0C:4C:9A:E6:D3:8F:1A:61:C7:DC:25
	MD5 Fingerprint=0xD4:74:DE:57:5C:39:B2:D3:9C:85:83:C5:C0:65:49:8A
	Non-critical OIDs
	  -SubjectKeyIdentifier(2.5.29.14) = <UNSUPPORTED>
	  -AuthorityKeyIdentifier(2.5.29.35) = <UNSUPPORTED>
	Critical OIDs
	  -KeyUsage(2.5.29.15) = [nonrepudiation keyencipherment ]
	  -BasicConstraints(2.5.29.19) = [TRUE ]

	[Server analysis]
	ACHIEVABLE_ENCRYPTION_STRENGTH=strong encryption (96-bit or more)
	CRIME_VULNERABLE=protected
	MINIMAL_ENCRYPTION_STRENGTH=strong encryption (96-bit or more)
	BEAST_VULNERABLE=vulnerable - See more at: http://www.securitycurmudgeon.com/#sthash.9HDq1HT5.dpuf
</code>
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
