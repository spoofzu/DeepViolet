package com.mps.deepviolet.api.fingerprint;

import com.mps.deepviolet.api.tls.ClientHelloConfig;
import com.mps.deepviolet.api.tls.TlsMetadata;
import com.mps.deepviolet.api.tls.TlsSocket;

/**
 * TLS Server Fingerprint computation.
 *
 * <p>TLS Server Probe Fingerprinting analyzes how a server responds to specially crafted
 * TLS ClientHello messages. By sending 10 different probes that vary cipher suites,
 * extensions, and TLS versions, this technique creates a unique 30-character
 * probe fingerprint based on the server's selection behavior.</p>
 *
 * <h2>What Fingerprints Identify</h2>
 * <ul>
 *   <li><strong>Server's cipher selection behavior</strong> - How the server chooses ciphers from offered options</li>
 *   <li><strong>Extension ordering in responses</strong> - The order and presence of TLS extensions</li>
 *   <li><strong>TLS version negotiation patterns</strong> - How the server handles version negotiation</li>
 *   <li><strong>Deployment-specific configuration</strong> - Settings unique to a server or infrastructure</li>
 * </ul>
 *
 * <h2>What Fingerprints Do NOT Identify</h2>
 * <ul>
 *   <li><strong>Specific software</strong> - Cannot definitively identify nginx, Apache, IIS, etc.</li>
 *   <li><strong>Software version</strong> - Cannot determine the version of server software</li>
 *   <li><strong>Underlying OS</strong> - Cannot reliably identify the operating system</li>
 *   <li><strong>Universal software signatures</strong> - Same software can produce different fingerprints</li>
 * </ul>
 *
 * <h2>Use Cases</h2>
 * <ul>
 *   <li><strong>Grouping</strong> - "These 50 servers behave identically" (same infrastructure)</li>
 *   <li><strong>Change Detection</strong> - Alert when a server's TLS behavior changes</li>
 *   <li><strong>Threat Hunting</strong> - Distinctive fingerprints for malware C2 servers</li>
 *   <li><strong>NOT</strong> - "This is definitely nginx" (software identification)</li>
 * </ul>
 *
 * <h2>Probe Fingerprint Structure</h2>
 * <ul>
 *   <li>Characters 1-30: Cipher+version codes from 10 probes (3 chars each)</li>
 * </ul>
 *
 * <p>Technique inspired by Salesforce's JARM: <a href="https://github.com/salesforce/jarm">https://github.com/salesforce/jarm</a></p>
 *
 * @see TlsBehaviorProbes
 */
public class TlsServerFingerprint {

    private TlsServerFingerprint() {}

    private static final int PROBE_TIMEOUT_MS = 5000;
    private static final int PROBE_COUNT = 10;

    /**
     * Compute TLS probe fingerprint for a host.
     *
     * <p>Sends 10 specially crafted ClientHello messages and analyzes the
     * ServerHello responses to create a probe fingerprint that characterizes
     * the server's TLS selection behavior.</p>
     *
     * @param host Target hostname
     * @param port Target port (usually 443)
     * @return 30-character TLS probe fingerprint, or null on complete failure
     */
    public static String compute(String host, int port) {
        StringBuilder cipherVersionCodes = new StringBuilder(30);

        for (int i = 1; i <= PROBE_COUNT; i++) {
            String code;

            try {
                ClientHelloConfig config = TlsBehaviorProbes.getProbe(i);
                TlsSocket socket = new TlsSocket(host, port);
                socket.setClientHelloConfig(config);
                socket.setConnectTimeoutMs(PROBE_TIMEOUT_MS);
                socket.setReadTimeoutMs(PROBE_TIMEOUT_MS);

                try {
                    TlsMetadata metadata = socket.performHandshake();

                    if (metadata.isConnectionSucceeded() && metadata.getServerHello() != null) {
                        code = metadata.getFingerprintCode();
                    } else {
                        code = "|||"; // Server refused
                    }
                } finally {
                    socket.close();
                }
            } catch (Exception e) {
                // Connection failed or protocol error
                code = "|||";
            }

            cipherVersionCodes.append(code);
        }

        return cipherVersionCodes.toString();
    }

    /**
     * Compute TLS probe fingerprint with default HTTPS port.
     *
     * @param host Target hostname
     * @return 30-character TLS probe fingerprint
     */
    public static String compute(String host) {
        return compute(host, 443);
    }

    /**
     * Parse a TLS probe fingerprint into its components.
     *
     * @param fingerprint The 30-character probe fingerprint string
     * @return Parsed components, or null if invalid
     */
    public static FingerprintComponents parse(String fingerprint) {
        if (fingerprint == null || fingerprint.length() != 30) {
            return null;
        }

        String[] probeCodes = new String[10];
        for (int i = 0; i < 10; i++) {
            probeCodes[i] = fingerprint.substring(i * 3, (i + 1) * 3);
        }

        return new FingerprintComponents(probeCodes);
    }

    /**
     * Check if a TLS fingerprint indicates no TLS support.
     * This happens when all probes fail (all |||).
     *
     * @param fingerprint The fingerprint to check
     * @return true if all probes failed, indicating no TLS support
     */
    public static boolean isNoTlsSupport(String fingerprint) {
        if (fingerprint == null || fingerprint.length() != 30) {
            return true;
        }

        // Check if all probe codes are "|||"
        for (int i = 0; i < 10; i++) {
            String code = fingerprint.substring(i * 3, (i + 1) * 3);
            if (!code.equals("|||")) {
                return false;
            }
        }
        return true;
    }

    /**
     * Get a human-readable summary of a TLS fingerprint.
     *
     * @param fingerprint The fingerprint to summarize
     * @return Human-readable summary string
     */
    public static String summarize(String fingerprint) {
        if (fingerprint == null || fingerprint.length() != 30) {
            return "Invalid fingerprint";
        }

        if (isNoTlsSupport(fingerprint)) {
            return "No TLS support detected";
        }

        StringBuilder sb = new StringBuilder();

        // Count successful probes
        int successCount = 0;
        boolean hasTls13 = false;
        boolean hasTls12 = false;

        for (int i = 0; i < 10; i++) {
            String code = fingerprint.substring(i * 3, (i + 1) * 3);
            if (!code.equals("|||")) {
                successCount++;
                char versionChar = code.charAt(1);
                if (versionChar == '3') hasTls13 = true;
                if (versionChar == '2') hasTls12 = true;
            }
        }

        sb.append("Probes successful: ").append(successCount).append("/10");

        if (hasTls13 && hasTls12) {
            sb.append(", TLS 1.3+1.2");
        } else if (hasTls13) {
            sb.append(", TLS 1.3 only");
        } else if (hasTls12) {
            sb.append(", TLS 1.2 only");
        }

        return sb.toString();
    }

    /**
     * Container for parsed TLS probe fingerprint components.
     *
     * <p>Provides access to individual probe codes
     * that make up a TLS probe fingerprint.</p>
     */
    public static class FingerprintComponents {
        private final String[] probeCodes;

        /** Create fingerprint components from probe codes.
         *  @param probeCodes array of probe result codes */
        public FingerprintComponents(String[] probeCodes) {
            this.probeCodes = probeCodes;
        }

        /**
         * Get all probe codes as an array.
         * @return Copy of the probe codes array
         */
        public String[] getProbeCodes() {
            return probeCodes.clone();
        }

        /**
         * Get a specific probe code (1-indexed).
         * @param probe Probe number from 1 to 10
         * @return The 3-character probe code
         * @throws IllegalArgumentException if probe number is out of range
         */
        public String getProbeCode(int probe) {
            if (probe < 1 || probe > 10) {
                throw new IllegalArgumentException("Probe must be 1-10");
            }
            return probeCodes[probe - 1];
        }

        /**
         * Get the cipher character from a probe code.
         * @param probe Probe number from 1 to 10
         * @return Single character representing the cipher selection
         */
        public String getCipherChar(int probe) {
            return String.valueOf(getProbeCode(probe).charAt(0));
        }

        /**
         * Get the version character from a probe code.
         * @param probe Probe number from 1 to 10
         * @return Single character representing the TLS version
         */
        public String getVersionChar(int probe) {
            return String.valueOf(getProbeCode(probe).charAt(1));
        }

        /**
         * Get the extension character from a probe code.
         * @param probe Probe number from 1 to 10
         * @return Single character representing extension count
         */
        public String getExtensionChar(int probe) {
            return String.valueOf(getProbeCode(probe).charAt(2));
        }

        /**
         * Check if a specific probe succeeded.
         * @param probe Probe number from 1 to 10
         * @return true if the probe received a valid response
         */
        public boolean probeSucceeded(int probe) {
            return !getProbeCode(probe).equals("|||");
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("FingerprintComponents[\n");
            for (int i = 1; i <= 10; i++) {
                sb.append("  Probe ").append(i).append(": ").append(getProbeCode(i));
                sb.append(" (").append(TlsBehaviorProbes.getProbeDescription(i)).append(")\n");
            }
            sb.append("]");
            return sb.toString();
        }
    }
}
