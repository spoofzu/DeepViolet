package com.mps.deepviolet.api.tls;

import java.util.Arrays;

/**
 * Container for a TLS extension type and its data.
 * Used to capture all extensions from ServerHello for analysis and TLS server fingerprinting.
 */
public class TlsExtension {

    /** Server Name Indication (SNI). */
    public static final int SERVER_NAME = 0x0000;
    /** Maximum fragment length negotiation. */
    public static final int MAX_FRAGMENT_LENGTH = 0x0001;
    /** Client certificate URL. */
    public static final int CLIENT_CERTIFICATE_URL = 0x0002;
    /** Trusted CA keys. */
    public static final int TRUSTED_CA_KEYS = 0x0003;
    /** Truncated HMAC. */
    public static final int TRUNCATED_HMAC = 0x0004;
    /** OCSP stapling (status_request). */
    public static final int STATUS_REQUEST = 0x0005;
    /** User mapping. */
    public static final int USER_MAPPING = 0x0006;
    /** Client authorization. */
    public static final int CLIENT_AUTHZ = 0x0007;
    /** Server authorization. */
    public static final int SERVER_AUTHZ = 0x0008;
    /** Certificate type. */
    public static final int CERT_TYPE = 0x0009;
    /** Supported groups (elliptic curves). */
    public static final int SUPPORTED_GROUPS = 0x000a;
    /** EC point formats. */
    public static final int EC_POINT_FORMATS = 0x000b;
    /** Secure Remote Password (SRP). */
    public static final int SRP = 0x000c;
    /** Signature algorithms. */
    public static final int SIGNATURE_ALGORITHMS = 0x000d;
    /** Use SRTP. */
    public static final int USE_SRTP = 0x000e;
    /** Heartbeat. */
    public static final int HEARTBEAT = 0x000f;
    /** Application-Layer Protocol Negotiation. */
    public static final int ALPN = 0x0010;
    /** Status request v2. */
    public static final int STATUS_REQUEST_V2 = 0x0011;
    /** Signed Certificate Timestamp (Certificate Transparency). */
    public static final int SIGNED_CERT_TIMESTAMP = 0x0012;
    /** Client certificate type. */
    public static final int CLIENT_CERTIFICATE_TYPE = 0x0013;
    /** Server certificate type. */
    public static final int SERVER_CERTIFICATE_TYPE = 0x0014;
    /** Padding. */
    public static final int PADDING = 0x0015;
    /** Encrypt-then-MAC. */
    public static final int ENCRYPT_THEN_MAC = 0x0016;
    /** Extended master secret. */
    public static final int EXTENDED_MASTER_SECRET = 0x0017;
    /** Token binding. */
    public static final int TOKEN_BINDING = 0x0018;
    /** Cached info. */
    public static final int CACHED_INFO = 0x0019;
    /** Compress certificate. */
    public static final int COMPRESS_CERTIFICATE = 0x001b;
    /** Record size limit. */
    public static final int RECORD_SIZE_LIMIT = 0x001c;
    /** Password protect. */
    public static final int PWD_PROTECT = 0x001d;
    /** Password clear. */
    public static final int PWD_CLEAR = 0x001e;
    /** Password salt. */
    public static final int PASSWORD_SALT = 0x001f;
    /** Session ticket. */
    public static final int SESSION_TICKET = 0x0023;
    /** Pre-shared key. */
    public static final int PRE_SHARED_KEY = 0x0029;
    /** Early data (0-RTT). */
    public static final int EARLY_DATA = 0x002a;
    /** Supported versions (TLS 1.3 version negotiation). */
    public static final int SUPPORTED_VERSIONS = 0x002b;
    /** Cookie. */
    public static final int COOKIE = 0x002c;
    /** PSK key exchange modes. */
    public static final int PSK_KEY_EXCHANGE_MODES = 0x002d;
    /** Certificate authorities. */
    public static final int CERTIFICATE_AUTHORITIES = 0x002f;
    /** OID filters. */
    public static final int OID_FILTERS = 0x0030;
    /** Post-handshake authentication. */
    public static final int POST_HANDSHAKE_AUTH = 0x0031;
    /** Signature algorithms for certificates. */
    public static final int SIGNATURE_ALGORITHMS_CERT = 0x0032;
    /** Key share (TLS 1.3). */
    public static final int KEY_SHARE = 0x0033;
    /** Renegotiation info. */
    public static final int RENEGOTIATION_INFO = 0xff01;

    /** GREASE values (RFC 8701) for fingerprint evasion testing. */
    public static final int[] GREASE_VALUES = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
    };

    private final int type;
    private final byte[] data;

    /** Create a TLS extension.
     *  @param type extension type code
     *  @param data extension data bytes */
    public TlsExtension(int type, byte[] data) {
        this.type = type;
        this.data = data != null ? data.clone() : new byte[0];
    }

    /** Returns the extension type code.
     *  @return type code */
    public int getType() {
        return type;
    }

    /** Returns a copy of the extension data.
     *  @return extension data bytes */
    public byte[] getData() {
        return data.clone();
    }

    /** Returns the length of the extension data.
     *  @return data length in bytes */
    public int getDataLength() {
        return data.length;
    }

    /**
     * Check if this extension is a GREASE value.
     * @return true if this is a GREASE extension
     */
    public boolean isGrease() {
        for (int grease : GREASE_VALUES) {
            if (type == grease) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get human-readable name for this extension type.
     * @return extension type name
     */
    public String getTypeName() {
        return getExtensionTypeName(type);
    }

    /**
     * Get human-readable name for any extension type.
     * @param type extension type code
     * @return human-readable name
     */
    public static String getExtensionTypeName(int type) {
        switch (type) {
            case SERVER_NAME: return "server_name";
            case MAX_FRAGMENT_LENGTH: return "max_fragment_length";
            case CLIENT_CERTIFICATE_URL: return "client_certificate_url";
            case TRUSTED_CA_KEYS: return "trusted_ca_keys";
            case TRUNCATED_HMAC: return "truncated_hmac";
            case STATUS_REQUEST: return "status_request";
            case SUPPORTED_GROUPS: return "supported_groups";
            case EC_POINT_FORMATS: return "ec_point_formats";
            case SIGNATURE_ALGORITHMS: return "signature_algorithms";
            case USE_SRTP: return "use_srtp";
            case HEARTBEAT: return "heartbeat";
            case ALPN: return "application_layer_protocol_negotiation";
            case STATUS_REQUEST_V2: return "status_request_v2";
            case SIGNED_CERT_TIMESTAMP: return "signed_certificate_timestamp";
            case PADDING: return "padding";
            case ENCRYPT_THEN_MAC: return "encrypt_then_mac";
            case EXTENDED_MASTER_SECRET: return "extended_master_secret";
            case SESSION_TICKET: return "session_ticket";
            case PRE_SHARED_KEY: return "pre_shared_key";
            case EARLY_DATA: return "early_data";
            case SUPPORTED_VERSIONS: return "supported_versions";
            case COOKIE: return "cookie";
            case PSK_KEY_EXCHANGE_MODES: return "psk_key_exchange_modes";
            case CERTIFICATE_AUTHORITIES: return "certificate_authorities";
            case POST_HANDSHAKE_AUTH: return "post_handshake_auth";
            case SIGNATURE_ALGORITHMS_CERT: return "signature_algorithms_cert";
            case KEY_SHARE: return "key_share";
            case RENEGOTIATION_INFO: return "renegotiation_info";
            default:
                // Check for GREASE
                for (int grease : GREASE_VALUES) {
                    if (type == grease) {
                        return "GREASE";
                    }
                }
                return String.format("unknown(0x%04x)", type);
        }
    }

    /**
     * Check if a type value is a GREASE value.
     * @param value the value to check
     * @return true if it is a GREASE value
     */
    public static boolean isGreaseValue(int value) {
        for (int grease : GREASE_VALUES) {
            if (value == grease) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return String.format("TlsExtension[type=%s(0x%04x), length=%d]",
                getTypeName(), type, data.length);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        TlsExtension other = (TlsExtension) obj;
        return type == other.type && Arrays.equals(data, other.data);
    }

    @Override
    public int hashCode() {
        int result = type;
        result = 31 * result + Arrays.hashCode(data);
        return result;
    }
}
