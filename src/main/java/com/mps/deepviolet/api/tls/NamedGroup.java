package com.mps.deepviolet.api.tls;

/**
 * Constants and helpers for IANA TLS Named Groups (RFC 8446 §4.2.7).
 *
 * Covers classical elliptic-curve / finite-field groups and the
 * post-quantum (PQ) hybrid key-exchange groups registered with IANA.
 */
public final class NamedGroup {

    private NamedGroup() { }

    /** NIST P-256 elliptic curve (secp256r1). */
    public static final int SECP256R1 = 0x0017;
    /** NIST P-384 elliptic curve (secp384r1). */
    public static final int SECP384R1 = 0x0018;
    /** NIST P-521 elliptic curve (secp521r1). */
    public static final int SECP521R1 = 0x0019;
    /** Curve25519 Diffie-Hellman function. */
    public static final int X25519    = 0x001d;
    /** Curve448 Diffie-Hellman function. */
    public static final int X448      = 0x001e;
    /** 2048-bit finite-field Diffie-Hellman group. */
    public static final int FFDHE2048 = 0x0100;
    /** 3072-bit finite-field Diffie-Hellman group. */
    public static final int FFDHE3072 = 0x0101;

    /** PQ hybrid: secp256r1 + ML-KEM-768 (RFC-ietf-tls-ecdhe-mlkem-04). */
    public static final int SECP256R1_MLKEM768  = 0x11EB; // 4587
    /** PQ hybrid: X25519 + ML-KEM-768 (RFC-ietf-tls-ecdhe-mlkem-04). */
    public static final int X25519_MLKEM768     = 0x11EC; // 4588
    /** PQ hybrid: secp384r1 + ML-KEM-1024 (RFC-ietf-tls-ecdhe-mlkem-04). */
    public static final int SECP384R1_MLKEM1024 = 0x11ED; // 4589

    /** Pure post-quantum: ML-KEM-768 (draft-connolly-tls-mlkem-key-agreement-05). */
    public static final int MLKEM768  = 0x0201; // 513
    /** Pure post-quantum: ML-KEM-1024 (draft-connolly-tls-mlkem-key-agreement-05). */
    public static final int MLKEM1024 = 0x0202; // 514

    /**
     * Return a human-readable name for the given group code.
     *
     * @param groupCode IANA named-group code
     * @return name such as "X25519" or "X25519MLKEM768", or a hex string for unknown codes
     */
    public static String getName(int groupCode) {
        return switch (groupCode) {
            case SECP256R1           -> "secp256r1";
            case SECP384R1           -> "secp384r1";
            case SECP521R1           -> "secp521r1";
            case X25519              -> "X25519";
            case X448                -> "X448";
            case FFDHE2048           -> "ffdhe2048";
            case FFDHE3072           -> "ffdhe3072";
            case SECP256R1_MLKEM768  -> "SecP256r1MLKEM768";
            case X25519_MLKEM768     -> "X25519MLKEM768";
            case SECP384R1_MLKEM1024 -> "SecP384r1MLKEM1024";
            case MLKEM768            -> "MLKEM768";
            case MLKEM1024           -> "MLKEM1024";
            default -> String.format("0x%04x", groupCode);
        };
    }

    /** All known PQ groups, ordered hybrid-first (most commonly deployed). */
    public static final int[] PQ_GROUPS = {
        X25519_MLKEM768,
        SECP256R1_MLKEM768,
        SECP384R1_MLKEM1024,
        MLKEM768,
        MLKEM1024,
    };

    /**
     * Return a classical fallback group for the given PQ group.
     * Used by the per-group PQ probe to pair each PQ group with a classical
     * alternative so the server always has a viable option.
     *
     * @param pqGroup a post-quantum group code
     * @return classical fallback (secp256r1 for secp256r1-based hybrids, X25519 otherwise)
     */
    public static int classicalFallback(int pqGroup) {
        return switch (pqGroup) {
            case SECP256R1_MLKEM768  -> SECP256R1;
            case SECP384R1_MLKEM1024 -> SECP384R1;
            default -> X25519;
        };
    }

    /**
     * Test whether the given group code is a post-quantum or hybrid-PQ group.
     *
     * @param groupCode IANA named-group code
     * @return true for PQ hybrid and pure PQ groups
     */
    public static boolean isPostQuantum(int groupCode) {
        return groupCode == X25519_MLKEM768
            || groupCode == SECP256R1_MLKEM768
            || groupCode == SECP384R1_MLKEM1024
            || groupCode == MLKEM768
            || groupCode == MLKEM1024;
    }
}
