package com.mps.deepviolet.validate;

import java.io.PrintStream;
import java.math.BigInteger;
import java.net.URL;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.mps.deepviolet.api.DeepVioletException;
import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.IX509Certificate;

/**
 * Validates DV API scan results against openssl for the same host.
 * Runs both tools, normalizes the output, and compares field-by-field.
 *
 * <p>Can be used as a standalone CLI tool or invoked programmatically.</p>
 *
 * <pre>
 * java -jar dvvalidate.jar google.com
 * java -jar dvvalidate.jar --json expired.badssl.com
 * </pre>
 *
 * @see OpensslRunner
 * @see FieldNormalizer
 */
public class ApiValidator {

    /** Creates a new validator instance. */
    public ApiValidator() {}

    private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.validate.ApiValidator");

    /**
     * Redirects logback's ConsoleAppender to stderr so validation output on
     * stdout is not polluted by DV API log messages.
     */
    private static void redirectLogbackToStderr() {
        try {
            ch.qos.logback.classic.LoggerContext ctx =
                    (ch.qos.logback.classic.LoggerContext) LoggerFactory.getILoggerFactory();
            ch.qos.logback.classic.Logger root = ctx.getLogger(
                    ch.qos.logback.classic.Logger.ROOT_LOGGER_NAME);
            java.util.Iterator<ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent>> it =
                    root.iteratorForAppenders();
            while (it.hasNext()) {
                ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent> appender = it.next();
                if (appender instanceof ch.qos.logback.core.ConsoleAppender) {
                    ((ch.qos.logback.core.ConsoleAppender<?>) appender).setTarget("System.err");
                    appender.stop();
                    appender.start();
                }
            }
        } catch (Exception ignored) {
            // If logback isn't on the classpath or config differs, skip silently
        }
    }

    /**
     * Standalone JAR entry point.
     *
     * @param args command-line arguments: {@code <host> [--port <port>] [--json] [--help]}
     */
    public static void main(String[] args) {
        redirectLogbackToStderr();

        if (args.length == 0 || "--help".equals(args[0]) || "-h".equals(args[0])) {
            printUsage();
            System.exit(0);
            return;
        }

        String host = null;
        int port = 443;
        boolean json = false;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--port":
                    if (i + 1 < args.length) {
                        try {
                            port = Integer.parseInt(args[++i]);
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid port: " + args[i]);
                            System.exit(1);
                        }
                    }
                    break;
                case "--json":
                    json = true;
                    break;
                case "--help":
                case "-h":
                    printUsage();
                    System.exit(0);
                    return;
                default:
                    if (!args[i].startsWith("-")) {
                        host = args[i];
                    }
                    break;
            }
        }

        if (host == null) {
            System.err.println("Error: No host specified.");
            printUsage();
            System.exit(1);
            return;
        }

        ApiValidator validator = new ApiValidator();
        ComparisonResult result = validator.validate(host, port);

        if (json) {
            validator.printJson(result, System.out);
        } else {
            validator.printResult(result, System.out);
        }

        System.exit(result.isDvSessionSucceeded() && result.isAllMatched() ? 0 : 1);
    }

    private static void printUsage() {
        System.out.println("Usage: dvvalidate <host> [--port <port>] [--json] [--help]");
        System.out.println();
        System.out.println("Validates DeepViolet API results against openssl for a host.");
        System.out.println();
        System.out.println("Arguments:");
        System.out.println("  <host>          Host to validate (e.g., google.com)");
        System.out.println("  --port <port>   Port number (default: 443)");
        System.out.println("  --json          Output as JSON instead of table");
        System.out.println("  --help, -h      Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  dvvalidate google.com");
        System.out.println("  dvvalidate expired.badssl.com");
        System.out.println("  dvvalidate --json github.com");
        System.out.println("  dvvalidate example.com --port 8443");
    }

    /**
     * Validate one server on port 443.
     *
     * @param host hostname to validate
     * @return comparison result with field-by-field match details
     */
    public ComparisonResult validate(String host) {
        return validate(host, 443);
    }

    /**
     * Validate one server on a custom port.
     *
     * @param host hostname to validate
     * @param port TCP port to connect to
     * @return comparison result with field-by-field match details
     */
    public ComparisonResult validate(String host, int port) {
        redirectLogbackToStderr();

        ComparisonResult result = new ComparisonResult();
        result.host = host;
        result.port = port;

        // Check openssl availability
        if (!OpensslRunner.isAvailable()) {
            result.dvSessionSucceeded = false;
            result.dvSessionError = "openssl not found — install openssl to use validation";
            result.computeSummary();
            return result;
        }

        result.opensslVersion = OpensslRunner.detectVersion();

        // Step 1: Run openssl
        logger.info("Running openssl against {}:{}...", host, port);
        OpensslResult opensslResult = OpensslRunner.scan(host, port);

        result.opensslData = opensslResult;

        if (!opensslResult.connectionSucceeded) {
            result.dvSessionSucceeded = false;
            result.dvSessionError = "Both DV and openssl failed to connect: " + opensslResult.connectionError;
            result.computeSummary();
            return result;
        }

        // Step 2: Run DV API
        // Raw TLS socket is now primary — no JSSE trust enforcement.
        // initializeSession() succeeds for any reachable server (good or bad certs).
        logger.info("Running DV API against {}:{}...", host, port);
        ISession session = null;
        IEngine eng = null;
        IX509Certificate cert = null;

        try {
            URL url = new URL("https://" + host + ":" + port + "/");
            session = DeepVioletFactory.initializeSession(url);
            eng = DeepVioletFactory.getEngine(session);
            cert = eng.getCertificate();
            result.dvSessionSucceeded = true;
        } catch (Exception e) {
            result.dvSessionSucceeded = false;
            result.dvSessionError = e.getMessage();
            logger.info("DV session failed: {}", e.getMessage());
        }

        // Step 3: Compare
        if (result.dvSessionSucceeded && cert != null && session != null) {
            compareFields(result, session, cert, opensslResult);
        }

        result.computeSummary();
        return result;
    }

    private void compareFields(ComparisonResult result, ISession session,
                                IX509Certificate cert, OpensslResult openssl) {

        OpensslResult.CertInfo osslCert = openssl.certificates.isEmpty() ? null : openssl.certificates.get(0);

        // --- Certificate fields ---

        if (osslCert != null) {
            // Subject DN
            String dvSubject = cert.getSubjectDN();
            String osslSubject = osslCert.subjectDN;
            boolean subjectMatch = FieldNormalizer.normalizeDN(dvSubject)
                    .equals(FieldNormalizer.normalizeDN(osslSubject));
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "subjectDN", dvSubject, osslSubject, subjectMatch));

            // Issuer DN
            String dvIssuer = cert.getIssuerDN();
            String osslIssuer = osslCert.issuerDN;
            boolean issuerMatch = FieldNormalizer.normalizeDN(dvIssuer)
                    .equals(FieldNormalizer.normalizeDN(osslIssuer));
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "issuerDN", dvIssuer, osslIssuer, issuerMatch));

            // Serial Number
            BigInteger dvSerial = cert.getCertificateSerialNumber();
            String dvSerialHex = dvSerial != null ? dvSerial.toString(16).toUpperCase() : "";
            String osslSerial = FieldNormalizer.normalizeSerial(osslCert.serialNumber);
            boolean serialMatch = FieldNormalizer.normalizeSerial(dvSerialHex).equals(osslSerial);
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "serialNumber", dvSerialHex, osslCert.serialNumber, serialMatch));

            // Version
            int dvVersion = cert.getCertificateVersion();
            int osslVersion = osslCert.version;
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "version",
                    String.valueOf(dvVersion), String.valueOf(osslVersion),
                    FieldNormalizer.compareIntegers(dvVersion, osslVersion)));

            // Signing Algorithm
            String dvSigAlg = cert.getSigningAlgorithm();
            String osslSigAlg = osslCert.signingAlgorithm;
            boolean sigAlgMatch = FieldNormalizer.normalizeSigningAlgorithm(dvSigAlg)
                    .equals(FieldNormalizer.normalizeSigningAlgorithm(osslSigAlg));
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "signingAlgorithm", dvSigAlg, osslSigAlg, sigAlgMatch));

            // Public Key Algorithm
            String dvKeyAlg = cert.getPublicKeyAlgorithm();
            String osslKeyAlg = osslCert.publicKeyAlgorithm;
            boolean keyAlgMatch = FieldNormalizer.normalizeKeyAlgorithm(dvKeyAlg)
                    .equals(FieldNormalizer.normalizeKeyAlgorithm(osslKeyAlg));
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "publicKeyAlgorithm", dvKeyAlg, osslKeyAlg, keyAlgMatch));

            // Public Key Size
            int dvKeySize = cert.getPublicKeySize();
            int osslKeySize = osslCert.publicKeySize;
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "publicKeySize",
                    String.valueOf(dvKeySize), String.valueOf(osslKeySize),
                    FieldNormalizer.compareIntegers(dvKeySize, osslKeySize)));

            // Public Key Curve (EC only)
            String dvCurve = cert.getPublicKeyCurve();
            String osslCurve = osslCert.publicKeyCurve;
            if (dvCurve != null || osslCurve != null) {
                boolean curveMatch = FieldNormalizer.normalizeCurveName(dvCurve)
                        .equals(FieldNormalizer.normalizeCurveName(osslCurve));
                result.fields.add(new ComparisonResult.FieldComparison(
                        "CERTIFICATE", "publicKeyCurve", dvCurve, osslCurve, curveMatch));
            }

            // Validity dates
            String dvNotBefore = cert.getNotValidBefore();
            String osslNotBefore = osslCert.notValidBefore;
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "notValidBefore", dvNotBefore, osslNotBefore,
                    FieldNormalizer.compareDates(dvNotBefore, osslNotBefore)));

            String dvNotAfter = cert.getNotValidAfter();
            String osslNotAfter = osslCert.notValidAfter;
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "notValidAfter", dvNotAfter, osslNotAfter,
                    FieldNormalizer.compareDates(dvNotAfter, osslNotAfter)));

            // Self-signed
            boolean dvSelfSigned = cert.isSelfSignedCertificate();
            boolean osslSelfSigned = osslCert.selfSigned;
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "isSelfSigned",
                    String.valueOf(dvSelfSigned), String.valueOf(osslSelfSigned),
                    dvSelfSigned == osslSelfSigned));

            // SAN count
            List<String> dvSans = cert.getSubjectAlternativeNames();
            int dvSanCount = dvSans != null ? dvSans.size() : 0;
            int osslSanCount = osslCert.sans.size();
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CERTIFICATE", "sanCount",
                    String.valueOf(dvSanCount), String.valueOf(osslSanCount),
                    FieldNormalizer.compareIntegers(dvSanCount, osslSanCount)));

            // Fingerprint
            String dvFp = cert.getCertificateFingerPrint();
            String osslFp = osslCert.sha256Fingerprint;
            if (dvFp != null || osslFp != null) {
                boolean fpMatch = FieldNormalizer.normalizeFingerprint(dvFp)
                        .equals(FieldNormalizer.normalizeFingerprint(osslFp));
                result.fields.add(new ComparisonResult.FieldComparison(
                        "CERTIFICATE", "fingerprint", dvFp, osslFp, fpMatch));
            }
        }

        // --- Connection fields ---

        // Negotiated protocol
        String dvProto = session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_PROTOCOL);
        String osslProto = openssl.negotiatedProtocol;
        result.fields.add(new ComparisonResult.FieldComparison(
                "CONNECTION", "negotiatedProtocol", dvProto, osslProto,
                FieldNormalizer.compareStringsNormalized(dvProto, osslProto)));

        // Negotiated cipher
        String dvCipher = session.getSessionPropertyValue(ISession.SESSION_PROPERTIES.NEGOTIATED_CIPHER_SUITE);
        String osslCipher = openssl.negotiatedCipher;
        // Cipher names may differ between IANA (DV) and OpenSSL naming
        boolean cipherMatch = FieldNormalizer.compareStringsNormalized(dvCipher, osslCipher);
        result.fields.add(new ComparisonResult.FieldComparison(
                "CONNECTION", "negotiatedCipher", dvCipher, osslCipher, cipherMatch));

        // Chain length
        try {
            IX509Certificate[] chain = cert.getCertificateChain();
            int dvChainLen = chain != null ? chain.length : 0;
            int osslChainLen = openssl.chainLength;
            result.fields.add(new ComparisonResult.FieldComparison(
                    "CONNECTION", "chainLength",
                    String.valueOf(dvChainLen), String.valueOf(osslChainLen),
                    FieldNormalizer.compareIntegers(dvChainLen, osslChainLen)));
        } catch (DeepVioletException e) {
            logger.warn("Failed to get DV certificate chain: {}", e.getMessage());
        }

        // OCSP stapling
        boolean dvOcsp = session.getStapledOcspResponse() != null;
        boolean osslOcsp = openssl.ocspStaplingPresent;
        result.fields.add(new ComparisonResult.FieldComparison(
                "CONNECTION", "ocspStapling",
                String.valueOf(dvOcsp), String.valueOf(osslOcsp),
                dvOcsp == osslOcsp));
    }

    /**
     * Prints the formatted comparison table to a PrintStream.
     *
     * @param result comparison result to display
     * @param out    stream to write the table to
     */
    public void printResult(ComparisonResult result, PrintStream out) {
        out.println();
        out.println("=== DeepViolet vs OpenSSL: " + result.host + ":" + result.port + " ===");
        if (result.opensslVersion != null) {
            out.println("OpenSSL: " + result.opensslVersion);
        }
        out.println();

        if (!result.dvSessionSucceeded) {
            out.println("  DV SESSION: FAILED (" + result.dvSessionError + ")");
            out.println("  RESULT: FAIL (unable to connect)");
            out.println();
            return;
        }

        // Group fields by section
        String currentSection = null;
        for (ComparisonResult.FieldComparison fc : result.fields) {
            if (!fc.section.equals(currentSection)) {
                currentSection = fc.section;
                out.println("  " + currentSection);
                out.printf("  %-24s %-24s %-24s %s%n",
                        "Field", "DeepViolet", "openssl", "Result");
                out.println("  " + "-".repeat(85));
            }

            String dvDisplay = truncate(fc.dvValue != null ? fc.dvValue : "(null)", 22);
            String osslDisplay = truncate(fc.opensslValue != null ? fc.opensslValue : "(null)", 22);
            String matchStr = fc.matched ? "MATCH" : "MISMATCH";

            out.printf("  %-24s %-24s %-24s %s%n",
                    fc.field, dvDisplay, osslDisplay, matchStr);
        }

        out.println();
        out.printf("  RESULT: %s (%d/%d fields)%n",
                result.allMatched ? "MATCH" : "MISMATCH",
                result.matchCount, result.totalFields);
        out.println();
    }

    /**
     * Prints the result as JSON.
     *
     * @param result comparison result to serialize
     * @param out    stream to write the JSON to
     */
    public void printJson(ComparisonResult result, PrintStream out) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        out.println(gson.toJson(result));
    }

    private static String truncate(String s, int maxLen) {
        if (s.length() <= maxLen) return s;
        return s.substring(0, maxLen - 3) + "...";
    }
}
