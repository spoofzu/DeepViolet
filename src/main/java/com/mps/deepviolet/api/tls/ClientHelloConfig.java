package com.mps.deepviolet.api.tls;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Configuration for building a TLS ClientHello message.
 * Used to customize probes for TLS server fingerprinting and other TLS analysis.
 *
 * TLS server fingerprinting uses 10 different ClientHello configurations to
 * characterize server behavior. Each configuration varies cipher suites,
 * extensions, and TLS versions to observe how servers respond differently
 * to different client configurations.
 *
 * @see com.mps.deepviolet.api.fingerprint.TlsServerFingerprint
 */
public class ClientHelloConfig {

    // TLS version constants
    public static final int TLS_1_0 = 0x0301;
    public static final int TLS_1_1 = 0x0302;
    public static final int TLS_1_2 = 0x0303;
    public static final int TLS_1_3 = 0x0304;
    public static final int SSL_3_0 = 0x0300;

    // Common cipher suite sets
    private static final List<Integer> ALL_CIPHERS = Arrays.asList(
            // TLS 1.3 ciphers (strongest first, matching openssl/browser defaults)
            0x1302, 0x1303, 0x1301, 0x1304, 0x1305,
            // TLS 1.2 ECDHE ciphers (key size first, then auth type — matching openssl)
            0xc02c, 0xc030, 0xc02b, 0xc02f,
            0xc024, 0xc028, 0xc023, 0xc027,
            0xc00a, 0xc014, 0xc009, 0xc013,
            // TLS 1.2 DHE ciphers
            0x009f, 0x009e, 0x006b, 0x0067,
            // TLS 1.2 RSA ciphers
            0x009d, 0x009c, 0x003d, 0x003c,
            0x0035, 0x002f, 0x00ff
    );

    private static final List<Integer> TLS13_ONLY_CIPHERS = Arrays.asList(
            0x1302, 0x1303, 0x1301, 0x1304, 0x1305
    );

    private static final List<Integer> TLS12_CIPHERS = Arrays.asList(
            0xc02c, 0xc030, 0xc02b, 0xc02f,
            0xc024, 0xc028, 0xc023, 0xc027,
            0xc00a, 0xc014, 0xc009, 0xc013,
            0x009f, 0x009e, 0x006b, 0x0067,
            0x009d, 0x009c, 0x003d, 0x003c,
            0x0035, 0x002f, 0x00ff
    );

    private static final List<Integer> WEAK_CIPHERS = Arrays.asList(
            0x0039, 0x0038, 0x0033, 0x0032,
            0x0016, 0x0013, 0x000a, 0x0007
    );

    private static final List<Integer> FORWARD_SECRECY_CIPHERS = Arrays.asList(
            0xc02c, 0xc030, 0xc02b, 0xc02f,
            0x009f, 0x009e, 0x006b, 0x0067
    );

    private int tlsVersion = TLS_1_2;
    private List<Integer> cipherSuites = new ArrayList<>(ALL_CIPHERS);
    private List<Integer> supportedVersions = new ArrayList<>();
    private List<Integer> extensions = new ArrayList<>();
    private boolean includeGrease = false;
    private String alpnProtocol = null;
    private boolean includeSupportedVersions = true;
    private boolean includeSignatureAlgorithms = true;
    private boolean includeSupportedGroups = true;
    private boolean includeKeyShare = false;
    private boolean includeStatusRequest = false;
    private boolean includeEcPointFormats = true;
    private List<Integer> supportedGroups = Arrays.asList(0x001d, 0x0017, 0x0018, 0x0019); // x25519, secp256r1, secp384r1, secp521r1

    public ClientHelloConfig() {
    }

    // ==================== Builder-style setters ====================

    public ClientHelloConfig setTlsVersion(int version) {
        this.tlsVersion = version;
        return this;
    }

    public ClientHelloConfig setCipherSuites(List<Integer> suites) {
        this.cipherSuites = new ArrayList<>(suites);
        return this;
    }

    public ClientHelloConfig setSupportedVersions(List<Integer> versions) {
        this.supportedVersions = new ArrayList<>(versions);
        return this;
    }

    public ClientHelloConfig setIncludeGrease(boolean include) {
        this.includeGrease = include;
        return this;
    }

    public ClientHelloConfig setAlpnProtocol(String protocol) {
        this.alpnProtocol = protocol;
        return this;
    }

    public ClientHelloConfig setIncludeSupportedVersions(boolean include) {
        this.includeSupportedVersions = include;
        return this;
    }

    public ClientHelloConfig setIncludeSignatureAlgorithms(boolean include) {
        this.includeSignatureAlgorithms = include;
        return this;
    }

    public ClientHelloConfig setIncludeSupportedGroups(boolean include) {
        this.includeSupportedGroups = include;
        return this;
    }

    public ClientHelloConfig setIncludeKeyShare(boolean include) {
        this.includeKeyShare = include;
        return this;
    }

    public ClientHelloConfig setIncludeStatusRequest(boolean include) {
        this.includeStatusRequest = include;
        return this;
    }

    public ClientHelloConfig setIncludeEcPointFormats(boolean include) {
        this.includeEcPointFormats = include;
        return this;
    }

    public ClientHelloConfig setSupportedGroups(List<Integer> groups) {
        this.supportedGroups = new ArrayList<>(groups);
        return this;
    }

    // ==================== Getters ====================

    public int getTlsVersion() {
        return tlsVersion;
    }

    public List<Integer> getCipherSuites() {
        return Collections.unmodifiableList(cipherSuites);
    }

    public List<Integer> getSupportedVersions() {
        if (supportedVersions.isEmpty()) {
            // Default: based on tlsVersion
            if (tlsVersion >= TLS_1_3) {
                return Arrays.asList(TLS_1_3, TLS_1_2, TLS_1_1, TLS_1_0);
            } else {
                return Collections.singletonList(tlsVersion);
            }
        }
        return Collections.unmodifiableList(supportedVersions);
    }

    public boolean isIncludeGrease() {
        return includeGrease;
    }

    public String getAlpnProtocol() {
        return alpnProtocol;
    }

    public boolean isIncludeSupportedVersions() {
        return includeSupportedVersions;
    }

    public boolean isIncludeSignatureAlgorithms() {
        return includeSignatureAlgorithms;
    }

    public boolean isIncludeSupportedGroups() {
        return includeSupportedGroups;
    }

    public boolean isIncludeKeyShare() {
        return includeKeyShare;
    }

    public boolean isIncludeStatusRequest() {
        return includeStatusRequest;
    }

    public boolean isIncludeEcPointFormats() {
        return includeEcPointFormats;
    }

    public List<Integer> getSupportedGroups() {
        return Collections.unmodifiableList(supportedGroups);
    }

    // ==================== Behavior Probe Presets ====================
    // For TLS server fingerprinting (inspired by Salesforce's JARM)

    /**
     * Create default configuration for normal TLS analysis.
     */
    public static ClientHelloConfig defaultConfig() {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_3)
                .setCipherSuites(ALL_CIPHERS)
                .setIncludeKeyShare(true)
                .setIncludeStatusRequest(true);
    }

    /**
     * Behavior Probe 1: TLS 1.2 with all standard ciphers, forward cipher order.
     */
    public static ClientHelloConfig behaviorProbe1() {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_2)
                .setCipherSuites(TLS12_CIPHERS)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_2));
    }

    /**
     * Behavior Probe 2: TLS 1.2 with all standard ciphers, reverse cipher order.
     */
    public static ClientHelloConfig behaviorProbe2() {
        List<Integer> reversed = new ArrayList<>(TLS12_CIPHERS);
        Collections.reverse(reversed);
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_2)
                .setCipherSuites(reversed)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_2));
    }

    /**
     * Behavior Probe 3: TLS 1.2 with all ciphers and ALPN h2.
     */
    public static ClientHelloConfig behaviorProbe3() {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_2)
                .setCipherSuites(TLS12_CIPHERS)
                .setAlpnProtocol("h2")
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_2));
    }

    /**
     * Behavior Probe 4: TLS 1.2 with rare ciphers (no ECC).
     */
    public static ClientHelloConfig behaviorProbe4() {
        List<Integer> noEcc = Arrays.asList(
                0x009f, 0x009e, 0x0067, 0x006b,
                0x009d, 0x009c, 0x003d, 0x003c,
                0x0035, 0x002f, 0x00ff
        );
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_2)
                .setCipherSuites(noEcc)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_2))
                .setIncludeSupportedGroups(false)
                .setIncludeEcPointFormats(false);
    }

    /**
     * Behavior Probe 5: TLS 1.1 only.
     */
    public static ClientHelloConfig behaviorProbe5() {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_1)
                .setCipherSuites(TLS12_CIPHERS)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_1));
    }

    /**
     * Behavior Probe 6: TLS 1.3 only with TLS 1.3 ciphers.
     */
    public static ClientHelloConfig behaviorProbe6() {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_3)
                .setCipherSuites(TLS13_ONLY_CIPHERS)
                .setIncludeKeyShare(true)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_3));
    }

    /**
     * Behavior Probe 7: TLS 1.3 with all ciphers (TLS 1.3 + 1.2).
     */
    public static ClientHelloConfig behaviorProbe7() {
        List<Integer> allCiphers = new ArrayList<>();
        allCiphers.addAll(TLS13_ONLY_CIPHERS);
        allCiphers.addAll(TLS12_CIPHERS);
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_3)
                .setCipherSuites(allCiphers)
                .setIncludeKeyShare(true)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_3, TLS_1_2));
    }

    /**
     * Behavior Probe 8: TLS 1.3 with ALPN h2.
     */
    public static ClientHelloConfig behaviorProbe8() {
        List<Integer> allCiphers = new ArrayList<>();
        allCiphers.addAll(TLS13_ONLY_CIPHERS);
        allCiphers.addAll(TLS12_CIPHERS);
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_3)
                .setCipherSuites(allCiphers)
                .setAlpnProtocol("h2")
                .setIncludeKeyShare(true)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_3, TLS_1_2));
    }

    /**
     * Behavior Probe 9: TLS 1.3 reverse cipher order.
     */
    public static ClientHelloConfig behaviorProbe9() {
        List<Integer> allCiphers = new ArrayList<>();
        allCiphers.addAll(TLS13_ONLY_CIPHERS);
        allCiphers.addAll(TLS12_CIPHERS);
        Collections.reverse(allCiphers);
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_3)
                .setCipherSuites(allCiphers)
                .setIncludeKeyShare(true)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_3, TLS_1_2));
    }

    /**
     * Behavior Probe 10: TLS 1.2 with forward secrecy ciphers only.
     */
    public static ClientHelloConfig behaviorProbe10() {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_2)
                .setCipherSuites(FORWARD_SECRECY_CIPHERS)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_2));
    }

    /**
     * Get behavior probe configuration by index (1-10).
     * @param probeNumber Probe number from 1 to 10
     * @return ClientHelloConfig for the specified probe
     * @throws IllegalArgumentException if probe number is out of range
     */
    public static ClientHelloConfig behaviorProbe(int probeNumber) {
        switch (probeNumber) {
            case 1: return behaviorProbe1();
            case 2: return behaviorProbe2();
            case 3: return behaviorProbe3();
            case 4: return behaviorProbe4();
            case 5: return behaviorProbe5();
            case 6: return behaviorProbe6();
            case 7: return behaviorProbe7();
            case 8: return behaviorProbe8();
            case 9: return behaviorProbe9();
            case 10: return behaviorProbe10();
            default:
                throw new IllegalArgumentException("Behavior probe number must be 1-10, got: " + probeNumber);
        }
    }

}
