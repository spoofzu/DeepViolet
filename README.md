<h1>DeepViolet, SSL/TLS Introspection Tool</h1><br/>
==========
<p/>
DeepViolet is a Java tool for introspection of SSL\TLS sessions.  DeepViolet can be run from the command line or via a GUI desktop application.  The tool was originally inspired by the work of Qualys SSL Labs and Ivan Ristić.  Original blog article post describing this project, http://www.securitycurmudgeon.com/2014/07/ssltls-introspection.html<br/>
<p/>
<b>TRY NOW</b>, 1) make sure Java 8+ installed, 2) download dvUI.jar to your desktop from the Release tab near the top of the screen, double-click to run 3) alternatively, download dvCMD.jar and run in your shell scripts.  Following are some sample command lines.
<p/>
The following command line executes a scan against www.github.com and includes all reporting sections.  The output of the report is the same as the sample included in this file.<br/>
<code>java -jar dvCMD.jar -serverurl https://www.github.com/</code>
<p/>
The following command line produces the same report but specifies each report section individually.  Including less sections increases the speed of the scan.<br/>
<code>java -jar dvCMD.jar -serverurl https://www.github.com/ -s thrcisn</code>
<p/>
The following command line produces exports the certificate on www.github.com to a PEM encoded file for offline use.
<code>java -jar dvCMD.jar -serverurl https://www.github.com/ -wc ~/milton/DeepViolet/github.pem</code><br/>
<p/>
Conversely the following command line reads a PEM encoded certificate and generates a report ('s' option) by default.  Note: the -rc option is mututually exclusive with other options.  The primary reason is that -rc is an offline reporting function.  Whereas other options are applicable for online servers.<br/>
<code>java -jar dvCMD.jar -rc ~/milton/DeepViolet/github.pem</code>
<p/>
If you need some help while your in the shell, command line help is available.<br/>
<code> java -jar dvCMD.jar -h</code><br/>
The help command produces output like the following.<br/>
<code>Miltons-Air:Desktop milton$ java -jar dvCMD.jar -h</code><br/>
<code>Starting headless via dvCMD</code><br/>
<code>DeepViolet user report directory available, name=/Users/milton/DeepViolet/</code><br/>
<code>usage: java -jar dvCMD.jar -serverurl <host|ip> [-wc <file> | -rc <file>]</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[-h -s{t|h|r|c|i|s|n}]</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Ex: dvCMD.jar -serverurl https://www.host.com/ -sections ts</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Where sections are the following,</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;;t=header section, h=host section, r=http response section,</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;c=connection characteristics section, i=ciphersuite section,</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;s=server certificate section, n=certificate chain section</code><br/>
<code>&nbsp;&nbsp;&nbsp;-h,--help                      Optional, print dvCMD help options.</code><br/>
<code>&nbsp;&nbsp;&nbsp;-rc,--readcertificate <arg>    Optional, read PEM encoded certificate</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;from disk. Ex: -rc ~/certs/mycert.pem</code><br/>
<code>&nbsp;&nbsp;&nbsp;-s,--sections <arg>            Optional, unspecified prints all section</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;or specify sections. [t|h|r|c|i|s|n]</code><br/>
<code>&nbsp;&nbsp;&nbsp;-u,--serverurl <arg>           Required for all options except</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-readcertificate, HTTPS server URL to</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;scan.</code><br/>
<code>&nbsp;&nbsp;&nbsp;-wc,--writecertificate <arg>   Optional, write PEM encoded certificate to</code><br/>
<code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;disk. Ex: -wc ~/certs/mycert.pem</code><br/>
<p/>
This program is provided for educational purposes.  Use at your own risk.  This program is only available in US English.<br/>
<i>This project leverages the works of other open source community projects.  Attention has been given to ensure attribution is provided as appropriate.</i>
