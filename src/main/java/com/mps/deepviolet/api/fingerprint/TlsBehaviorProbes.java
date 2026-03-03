package com.mps.deepviolet.api.fingerprint;

import com.mps.deepviolet.api.tls.ClientHelloConfig;

/**
 * TLS behavior probe definitions for server fingerprinting.
 *
 * <p>TLS server fingerprinting uses 10 different ClientHello probe configurations
 * to observe how servers respond to different client capabilities. Each probe varies:</p>
 * <ul>
 *   <li>TLS version advertised</li>
 *   <li>Cipher suite order and selection</li>
 *   <li>Extensions included</li>
 *   <li>ALPN protocols offered</li>
 * </ul>
 *
 * <p>By analyzing the server's responses to these varied probes, we can characterize
 * the server's TLS selection behavior and create a unique fingerprint.</p>
 *
 * <p>Technique inspired by Salesforce's JARM: <a href="https://github.com/salesforce/jarm">https://github.com/salesforce/jarm</a></p>
 *
 * @see TlsServerFingerprint
 */
public class TlsBehaviorProbes {

    /**
     * Total number of behavior probes.
     */
    public static final int PROBE_COUNT = 10;

    /**
     * Get probe configuration by number (1-10).
     *
     * @param probeNumber Probe number from 1 to 10
     * @return Configuration for the specified probe
     * @throws IllegalArgumentException if probe number is out of range
     */
    public static ClientHelloConfig getProbe(int probeNumber) {
        return ClientHelloConfig.behaviorProbe(probeNumber);
    }

    /**
     * Get a human-readable description of what each probe tests.
     *
     * @param probeNumber Probe number from 1 to 10
     * @return Description of the probe's purpose
     */
    public static String getProbeDescription(int probeNumber) {
        switch (probeNumber) {
            case 1:
                return "TLS 1.2 standard cipher order";
            case 2:
                return "TLS 1.2 reverse cipher order";
            case 3:
                return "TLS 1.2 with ALPN h2";
            case 4:
                return "TLS 1.2 no ECC support";
            case 5:
                return "TLS 1.1 only";
            case 6:
                return "TLS 1.3 only (TLS 1.3 ciphers)";
            case 7:
                return "TLS 1.3 with TLS 1.2 fallback";
            case 8:
                return "TLS 1.3 with ALPN h2";
            case 9:
                return "TLS 1.3 reverse cipher order";
            case 10:
                return "TLS 1.2 forward secrecy only";
            default:
                return "Unknown probe";
        }
    }

    /**
     * Check if a probe number is valid.
     *
     * @param probeNumber The probe number to validate
     * @return true if the probe number is between 1 and 10 inclusive
     */
    public static boolean isValidProbeNumber(int probeNumber) {
        return probeNumber >= 1 && probeNumber <= PROBE_COUNT;
    }
}
