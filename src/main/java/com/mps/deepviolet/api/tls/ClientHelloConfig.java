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

    /** TLS 1.0 protocol version (0x0301). */
    public static final int TLS_1_0 = 0x0301;
    /** TLS 1.1 protocol version (0x0302). */
    public static final int TLS_1_1 = 0x0302;
    /** TLS 1.2 protocol version (0x0303). */
    public static final int TLS_1_2 = 0x0303;
    /** TLS 1.3 protocol version (0x0304). */
    public static final int TLS_1_3 = 0x0304;
    /** SSL 3.0 protocol version (0x0300). */
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
    private boolean emptyKeyShare = false;
    private boolean includeStatusRequest = false;
    private boolean includeEcPointFormats = true;
    private List<Integer> supportedGroups = Arrays.asList(0x001d, 0x0017, 0x0018, 0x0019); // x25519, secp256r1, secp384r1, secp521r1

    /** Creates a ClientHelloConfig with default settings. */
    public ClientHelloConfig() {
    }

    // ==================== Builder-style setters ====================

    /** Sets the TLS record-layer version.
     *  @param version TLS record-layer version
     *  @return this config for chaining */
    public ClientHelloConfig setTlsVersion(int version) {
        this.tlsVersion = version;
        return this;
    }

    /** Sets the cipher suite list.
     *  @param suites cipher suite list
     *  @return this config for chaining */
    public ClientHelloConfig setCipherSuites(List<Integer> suites) {
        this.cipherSuites = new ArrayList<>(suites);
        return this;
    }

    /** Sets the supported TLS versions list.
     *  @param versions supported TLS versions
     *  @return this config for chaining */
    public ClientHelloConfig setSupportedVersions(List<Integer> versions) {
        this.supportedVersions = new ArrayList<>(versions);
        return this;
    }

    /** Controls whether GREASE values are included.
     *  @param include true to include GREASE values
     *  @return this config for chaining */
    public ClientHelloConfig setIncludeGrease(boolean include) {
        this.includeGrease = include;
        return this;
    }

    /** Sets the ALPN protocol name.
     *  @param protocol ALPN protocol name (e.g. "h2"), or null
     *  @return this config for chaining */
    public ClientHelloConfig setAlpnProtocol(String protocol) {
        this.alpnProtocol = protocol;
        return this;
    }

    /** Controls whether the supported_versions extension is included.
     *  @param include true to include the supported_versions extension
     *  @return this config for chaining */
    public ClientHelloConfig setIncludeSupportedVersions(boolean include) {
        this.includeSupportedVersions = include;
        return this;
    }

    /** Controls whether the signature_algorithms extension is included.
     *  @param include true to include the signature_algorithms extension
     *  @return this config for chaining */
    public ClientHelloConfig setIncludeSignatureAlgorithms(boolean include) {
        this.includeSignatureAlgorithms = include;
        return this;
    }

    /** Controls whether the supported_groups extension is included.
     *  @param include true to include the supported_groups extension
     *  @return this config for chaining */
    public ClientHelloConfig setIncludeSupportedGroups(boolean include) {
        this.includeSupportedGroups = include;
        return this;
    }

    /** Controls whether the key_share extension is included.
     *  @param include true to include the key_share extension
     *  @return this config for chaining */
    public ClientHelloConfig setIncludeKeyShare(boolean include) {
        this.includeKeyShare = include;
        return this;
    }

    /**
     * When true, the key_share extension is included but with an empty
     * client_shares list (zero key share entries).  This forces the server
     * to respond with a HelloRetryRequest, revealing its preferred group.
     * Implies {@code includeKeyShare = true}.
     *
     * @param empty true to send an empty key_share extension
     * @return this config for chaining
     */
    public ClientHelloConfig setEmptyKeyShare(boolean empty) {
        this.emptyKeyShare = empty;
        if (empty) {
            this.includeKeyShare = true;
        }
        return this;
    }

    /** Controls whether the status_request extension is included.
     *  @param include true to include the status_request extension
     *  @return this config for chaining */
    public ClientHelloConfig setIncludeStatusRequest(boolean include) {
        this.includeStatusRequest = include;
        return this;
    }

    /** Controls whether the ec_point_formats extension is included.
     *  @param include true to include the ec_point_formats extension
     *  @return this config for chaining */
    public ClientHelloConfig setIncludeEcPointFormats(boolean include) {
        this.includeEcPointFormats = include;
        return this;
    }

    /** Sets the supported named groups list.
     *  @param groups supported named groups
     *  @return this config for chaining */
    public ClientHelloConfig setSupportedGroups(List<Integer> groups) {
        this.supportedGroups = new ArrayList<>(groups);
        return this;
    }

    // ==================== Getters ====================

    /** Returns the TLS record-layer version.
     *  @return TLS version code */
    public int getTlsVersion() {
        return tlsVersion;
    }

    /** Returns the cipher suite list (unmodifiable).
     *  @return unmodifiable list of cipher suite codes */
    public List<Integer> getCipherSuites() {
        return Collections.unmodifiableList(cipherSuites);
    }

    /** Returns the supported_versions list, defaulting based on tlsVersion if not explicitly set.
     *  @return unmodifiable list of supported TLS version codes */
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

    /** Returns whether GREASE values are included.
     *  @return true if GREASE values are included */
    public boolean isIncludeGrease() {
        return includeGrease;
    }

    /** Returns the ALPN protocol name.
     *  @return the ALPN protocol name, or null */
    public String getAlpnProtocol() {
        return alpnProtocol;
    }

    /** Returns whether the supported_versions extension is included.
     *  @return true if the supported_versions extension is included */
    public boolean isIncludeSupportedVersions() {
        return includeSupportedVersions;
    }

    /** Returns whether the signature_algorithms extension is included.
     *  @return true if the signature_algorithms extension is included */
    public boolean isIncludeSignatureAlgorithms() {
        return includeSignatureAlgorithms;
    }

    /** Returns whether the supported_groups extension is included.
     *  @return true if the supported_groups extension is included */
    public boolean isIncludeSupportedGroups() {
        return includeSupportedGroups;
    }

    /** Returns whether the key_share extension is included.
     *  @return true if the key_share extension is included */
    public boolean isIncludeKeyShare() {
        return includeKeyShare;
    }

    /** Returns whether the key_share extension should contain an empty client_shares list.
     *  @return true if the key_share client_shares list is empty */
    public boolean isEmptyKeyShare() {
        return emptyKeyShare;
    }

    /** Returns whether the status_request extension is included.
     *  @return true if the status_request extension is included */
    public boolean isIncludeStatusRequest() {
        return includeStatusRequest;
    }

    /** Returns whether the ec_point_formats extension is included.
     *  @return true if the ec_point_formats extension is included */
    public boolean isIncludeEcPointFormats() {
        return includeEcPointFormats;
    }

    /** Returns the supported named groups list (unmodifiable).
     *  @return unmodifiable list of named group codes */
    public List<Integer> getSupportedGroups() {
        return Collections.unmodifiableList(supportedGroups);
    }

    /**
     * Build a ClientHello for probing whether the server supports a specific
     * post-quantum key exchange group.
     *
     * <p>Advertises <b>only</b> the target PQ group in
     * {@code supported_groups}, with an <b>empty</b> {@code key_share}
     * list.  This forces the server to either HelloRetryRequest for
     * the PQ group (supported) or abort with {@code handshake_failure}
     * (not supported).  No classical fallback is offered — this
     * eliminates server-preference ambiguity where a server that
     * supports PQ would still pick a classical group it prefers.</p>
     *
     * @param pqGroup the PQ named-group code to test
     *                (e.g. {@link NamedGroup#X25519_MLKEM768})
     * @return a ClientHelloConfig that probes for the specified PQ group
     */
    public static ClientHelloConfig pqProbe(int pqGroup) {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_3)
                .setCipherSuites(TLS13_ONLY_CIPHERS)
                .setSupportedGroups(Arrays.asList(pqGroup))
                .setEmptyKeyShare(true)            // empty key_share → forces HRR
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_3));
    }

    /**
     * Build a ClientHello for probing the server's post-quantum key exchange
     * <b>preference</b>.
     *
     * <p>Advertises both PQ hybrid and classical groups with PQ listed first
     * (matching Chrome/Firefox ordering), using an empty {@code key_share}
     * to force HelloRetryRequest.  The server's HRR reveals which group it
     * prefers when given the choice.  This directly answers "will it negotiate
     * PQ if presented?" without the ambiguity of the main handshake (which
     * only offers classical groups).</p>
     *
     * <p>Groups offered (in order):</p>
     * <ol>
     *   <li>X25519_MLKEM768 (0x11EC)</li>
     *   <li>SecP256r1_MLKEM768 (0x11EB)</li>
     *   <li>X25519 (0x001d)</li>
     *   <li>secp256r1 (0x0017)</li>
     * </ol>
     * <p>Pure PQ groups are excluded (draft-stage, not offered by browsers).</p>
     *
     * @return a ClientHelloConfig that probes PQ vs classical group preference
     */
    public static ClientHelloConfig pqPreferenceProbe() {
        return new ClientHelloConfig()
                .setTlsVersion(TLS_1_3)
                .setCipherSuites(TLS13_ONLY_CIPHERS)
                .setSupportedGroups(Arrays.asList(
                        NamedGroup.X25519_MLKEM768,    // PQ hybrid first
                        NamedGroup.SECP256R1_MLKEM768, // PQ hybrid second
                        NamedGroup.X25519,             // classical fallback
                        NamedGroup.SECP256R1           // classical fallback
                ))
                .setEmptyKeyShare(true)
                .setIncludeSupportedVersions(true)
                .setSupportedVersions(Arrays.asList(TLS_1_3));
    }

    // ==================== Behavior Probe Presets ====================
    // For TLS server fingerprinting (inspired by Salesforce's JARM)

    /**
     * Create default configuration for normal TLS analysis.
     *
     * @return a ClientHelloConfig with default TLS 1.3 settings
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
     *
     * @return the probe configuration
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
        // Probes are grouped by TLS version: 1=TLS 1.1, 2-6=TLS 1.2, 7-10=TLS 1.3
        switch (probeNumber) {
            case 1: return behaviorProbe5();   // TLS 1.1 only
            case 2: return behaviorProbe1();   // TLS 1.2 standard cipher order
            case 3: return behaviorProbe2();   // TLS 1.2 reverse cipher order
            case 4: return behaviorProbe3();   // TLS 1.2 with ALPN h2
            case 5: return behaviorProbe4();   // TLS 1.2 no ECC support
            case 6: return behaviorProbe10();  // TLS 1.2 forward secrecy only
            case 7: return behaviorProbe6();   // TLS 1.3 only (TLS 1.3 ciphers)
            case 8: return behaviorProbe7();   // TLS 1.3 with TLS 1.2 fallback
            case 9: return behaviorProbe8();   // TLS 1.3 with ALPN h2
            case 10: return behaviorProbe9();  // TLS 1.3 reverse cipher order
            default:
                throw new IllegalArgumentException("Behavior probe number must be 1-10, got: " + probeNumber);
        }
    }

}
