package com.mps.deepviolet.validate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Executes openssl commands via ProcessBuilder and parses the output to extract
 * TLS connection and certificate information for comparison against DV API results.
 */
class OpensslRunner {

    private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.validate.OpensslRunner");

    private static final int COMMAND_TIMEOUT_SECONDS = 15;

    private static String cachedVersion;

    // --- Regex patterns for parsing openssl output ---

    // s_client output
    private static final Pattern PROTOCOL_PATTERN = Pattern.compile(
            "Protocol\\s*:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern CIPHER_PATTERN = Pattern.compile(
            "Cipher\\s*(?:is|:)\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern OCSP_RESPONSE_PATTERN = Pattern.compile(
            "OCSP response:\\s*no response sent", Pattern.MULTILINE);
    private static final Pattern OCSP_RESPONSE_PRESENT_PATTERN = Pattern.compile(
            "OCSP Response Status:\\s*successful", Pattern.MULTILINE);

    // x509 -text output
    private static final Pattern SUBJECT_PATTERN = Pattern.compile(
            "Subject:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern ISSUER_PATTERN = Pattern.compile(
            "Issuer:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern SERIAL_PATTERN = Pattern.compile(
            "Serial Number:\\s*\\n?\\s*([0-9a-fA-F:]+)", Pattern.MULTILINE);
    private static final Pattern SERIAL_DECIMAL_PATTERN = Pattern.compile(
            "Serial Number:\\s*\\n?\\s*(\\d+)\\s*\\(", Pattern.MULTILINE);
    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "Version:\\s*(\\d+)", Pattern.MULTILINE);
    private static final Pattern SIG_ALG_PATTERN = Pattern.compile(
            "Signature Algorithm:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern PUB_KEY_ALG_PATTERN = Pattern.compile(
            "Public Key Algorithm:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern KEY_SIZE_PATTERN = Pattern.compile(
            "(\\d+)\\s*bit", Pattern.MULTILINE);
    private static final Pattern EC_CURVE_PATTERN = Pattern.compile(
            "ASN1 OID:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern NOT_BEFORE_PATTERN = Pattern.compile(
            "Not Before:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern NOT_AFTER_PATTERN = Pattern.compile(
            "Not After\\s*:\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern SAN_PATTERN = Pattern.compile(
            "X509v3 Subject Alternative Name:\\s*(?:critical)?\\s*\\n\\s*(.+)", Pattern.MULTILINE);
    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile(
            "SHA256 Fingerprint\\s*=\\s*(.+)", Pattern.MULTILINE);
    // LibreSSL uses "SHA256 Fingerprint", OpenSSL 3.x uses "sha256 Fingerprint"
    private static final Pattern FINGERPRINT_PATTERN_ALT = Pattern.compile(
            "(?:sha|SHA)256 Fingerprint\\s*=\\s*(.+)", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);

    /**
     * Checks if openssl is available on the system.
     *
     * @return true if openssl can be executed
     */
    static boolean isAvailable() {
        try {
            String version = detectVersion();
            return version != null && !version.isEmpty();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Detects and caches the openssl version string.
     */
    static String detectVersion() {
        if (cachedVersion != null) return cachedVersion;
        try {
            String output = runCommand("openssl", "version");
            cachedVersion = output.trim();
            return cachedVersion;
        } catch (Exception e) {
            logger.warn("Failed to detect openssl version: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Runs openssl s_client and x509 commands against the target host and parses
     * the results into an OpensslResult.
     */
    static OpensslResult scan(String host, int port) {
        OpensslResult result = new OpensslResult();
        result.opensslVersion = detectVersion();

        // Run s_client to get connection info and certificate chain
        String sClientOutput;
        try {
            sClientOutput = runSClient(host, port);
        } catch (Exception e) {
            logger.warn("openssl s_client failed for {}:{}: {}", host, port, e.getMessage());
            result.connectionSucceeded = false;
            result.connectionError = e.getMessage();
            return result;
        }

        if (sClientOutput == null || sClientOutput.isEmpty()) {
            result.connectionSucceeded = false;
            result.connectionError = "Empty response from openssl s_client";
            return result;
        }

        // Check for connection failure
        if (sClientOutput.contains("connect:errno=") || sClientOutput.contains("Connection refused")) {
            result.connectionSucceeded = false;
            result.connectionError = "Connection refused";
            return result;
        }

        result.connectionSucceeded = true;

        // Parse connection info from s_client
        result.negotiatedProtocol = extractFirst(PROTOCOL_PATTERN, sClientOutput);
        result.negotiatedCipher = extractFirst(CIPHER_PATTERN, sClientOutput);

        // OCSP stapling detection
        if (OCSP_RESPONSE_PRESENT_PATTERN.matcher(sClientOutput).find()) {
            result.ocspStaplingPresent = true;
        } else if (OCSP_RESPONSE_PATTERN.matcher(sClientOutput).find()) {
            result.ocspStaplingPresent = false;
        }

        // Extract PEM certificates from s_client -showcerts output
        List<String> pemCerts = extractPemCerts(sClientOutput);
        result.chainLength = pemCerts.size();

        // Parse each certificate
        for (String pem : pemCerts) {
            try {
                OpensslResult.CertInfo certInfo = parseCertificate(pem);
                if (certInfo != null) {
                    result.certificates.add(certInfo);
                }
            } catch (Exception e) {
                logger.warn("Failed to parse certificate: {}", e.getMessage());
            }
        }

        // Also get SHA256 fingerprint for end-entity cert
        if (!pemCerts.isEmpty()) {
            try {
                String fpOutput = runFingerprintCommand(pemCerts.get(0));
                if (fpOutput != null) {
                    String fp = extractFirst(FINGERPRINT_PATTERN_ALT, fpOutput);
                    if (fp != null && !result.certificates.isEmpty()) {
                        result.certificates.get(0).sha256Fingerprint = fp.trim();
                    }
                }
            } catch (Exception e) {
                logger.warn("Failed to get certificate fingerprint: {}", e.getMessage());
            }
        }

        return result;
    }

    /**
     * Runs openssl s_client with -showcerts and -status for OCSP stapling.
     */
    private static String runSClient(String host, int port) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(
                "openssl", "s_client",
                "-connect", host + ":" + port,
                "-servername", host,
                "-showcerts",
                "-status"
        );
        pb.redirectErrorStream(true);

        Process process = pb.start();

        // Close stdin immediately so s_client doesn't hang waiting for input
        process.getOutputStream().close();

        String output = readProcessOutput(process);
        boolean finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("openssl s_client timed out after " + COMMAND_TIMEOUT_SECONDS + "s");
        }

        return output;
    }

    /**
     * Pipes a PEM cert through openssl x509 -text -noout to parse its details.
     */
    private static OpensslResult.CertInfo parseCertificate(String pem) throws IOException, InterruptedException {
        String textOutput = runX509Text(pem);
        if (textOutput == null || textOutput.isEmpty()) return null;

        OpensslResult.CertInfo info = new OpensslResult.CertInfo();

        info.subjectDN = extractFirst(SUBJECT_PATTERN, textOutput);
        info.issuerDN = extractFirst(ISSUER_PATTERN, textOutput);

        // Serial number - try hex format first, then decimal
        info.serialNumber = extractFirst(SERIAL_PATTERN, textOutput);
        if (info.serialNumber == null) {
            String decimalSerial = extractFirst(SERIAL_DECIMAL_PATTERN, textOutput);
            if (decimalSerial != null) {
                try {
                    info.serialNumber = new java.math.BigInteger(decimalSerial).toString(16).toUpperCase();
                } catch (NumberFormatException e) {
                    info.serialNumber = decimalSerial;
                }
            }
        }

        String versionStr = extractFirst(VERSION_PATTERN, textOutput);
        if (versionStr != null) {
            try {
                info.version = Integer.parseInt(versionStr.trim());
            } catch (NumberFormatException ignored) {
            }
        }

        info.signingAlgorithm = extractFirst(SIG_ALG_PATTERN, textOutput);
        info.publicKeyAlgorithm = extractFirst(PUB_KEY_ALG_PATTERN, textOutput);

        String keySizeStr = extractFirst(KEY_SIZE_PATTERN, textOutput);
        if (keySizeStr != null) {
            try {
                info.publicKeySize = Integer.parseInt(keySizeStr.trim());
            } catch (NumberFormatException ignored) {
            }
        }

        info.publicKeyCurve = extractFirst(EC_CURVE_PATTERN, textOutput);
        info.notValidBefore = extractFirst(NOT_BEFORE_PATTERN, textOutput);
        info.notValidAfter = extractFirst(NOT_AFTER_PATTERN, textOutput);

        // Self-signed: subject == issuer
        if (info.subjectDN != null && info.issuerDN != null) {
            info.selfSigned = FieldNormalizer.normalizeDN(info.subjectDN)
                    .equals(FieldNormalizer.normalizeDN(info.issuerDN));
        }

        // SANs
        String sanLine = extractFirst(SAN_PATTERN, textOutput);
        if (sanLine != null) {
            String[] entries = sanLine.split(",");
            for (String entry : entries) {
                String trimmed = entry.trim();
                if (trimmed.startsWith("DNS:") || trimmed.startsWith("IP Address:")) {
                    info.sans.add(trimmed);
                }
            }
        }

        return info;
    }

    /**
     * Runs openssl x509 -text -noout on a PEM certificate.
     */
    private static String runX509Text(String pem) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(
                "openssl", "x509", "-text", "-noout"
        );
        pb.redirectErrorStream(true);

        Process process = pb.start();

        // Write PEM to stdin
        process.getOutputStream().write(pem.getBytes(StandardCharsets.UTF_8));
        process.getOutputStream().close();

        String output = readProcessOutput(process);
        boolean finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("openssl x509 timed out");
        }

        return output;
    }

    /**
     * Runs openssl x509 -fingerprint -sha256 on a PEM certificate.
     */
    private static String runFingerprintCommand(String pem) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(
                "openssl", "x509", "-fingerprint", "-sha256", "-noout"
        );
        pb.redirectErrorStream(true);

        Process process = pb.start();

        process.getOutputStream().write(pem.getBytes(StandardCharsets.UTF_8));
        process.getOutputStream().close();

        String output = readProcessOutput(process);
        boolean finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
        }

        return output;
    }

    /**
     * Extracts individual PEM certificate blocks from s_client -showcerts output.
     */
    static List<String> extractPemCerts(String sClientOutput) {
        List<String> certs = new ArrayList<>();
        String beginMarker = "-----BEGIN CERTIFICATE-----";
        String endMarker = "-----END CERTIFICATE-----";

        int searchFrom = 0;
        while (true) {
            int beginIdx = sClientOutput.indexOf(beginMarker, searchFrom);
            if (beginIdx < 0) break;
            int endIdx = sClientOutput.indexOf(endMarker, beginIdx);
            if (endIdx < 0) break;
            certs.add(sClientOutput.substring(beginIdx, endIdx + endMarker.length()));
            searchFrom = endIdx + endMarker.length();
        }

        return certs;
    }

    private static String runCommand(String... args) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(args);
        pb.redirectErrorStream(true);

        Process process = pb.start();
        String output = readProcessOutput(process);

        boolean finished = process.waitFor(COMMAND_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IOException("Command timed out: " + String.join(" ", args));
        }

        return output;
    }

    private static String readProcessOutput(Process process) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    private static String extractFirst(Pattern pattern, String input) {
        Matcher m = pattern.matcher(input);
        if (m.find()) {
            return m.group(1).trim();
        }
        return null;
    }
}
