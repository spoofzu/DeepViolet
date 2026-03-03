package com.mps.deepviolet.api.tls;

/**
 * Parsed ServerKeyExchange message for extracting key exchange parameters.
 * Supports DHE and ECDHE key exchange types.
 *
 * <p>DHE ServerKeyExchange structure:
 * <pre>
 *   dh_p:  2-byte length + prime bytes
 *   dh_g:  2-byte length + generator bytes
 *   dh_Ys: 2-byte length + public value bytes
 *   signature
 * </pre>
 *
 * <p>ECDHE ServerKeyExchange structure:
 * <pre>
 *   curve_type: 1 byte (3 = named_curve)
 *   named_curve: 2 bytes (curve ID)
 *   point: 1-byte length + EC point bytes
 *   signature
 * </pre>
 */
public class ServerKeyExchange {

    /** Named curve IDs to names (RFC 8422 / IANA TLS Supported Groups). */
    private static final String[] NAMED_CURVES = new String[0x0020];
    static {
        NAMED_CURVES[0x0017] = "secp256r1";
        NAMED_CURVES[0x0018] = "secp384r1";
        NAMED_CURVES[0x0019] = "secp521r1";
        NAMED_CURVES[0x001D] = "x25519";
        NAMED_CURVES[0x001E] = "x448";
        NAMED_CURVES[0x0015] = "secp256k1";
        NAMED_CURVES[0x0013] = "secp192r1";
        NAMED_CURVES[0x0016] = "secp224r1";
    }

    public enum KexType { DHE, ECDHE, UNKNOWN }

    private final KexType kexType;
    private final int dhPrimeSizeBits;
    private final int ecCurveId;
    private final String ecCurveName;

    private ServerKeyExchange(KexType kexType, int dhPrimeSizeBits, int ecCurveId, String ecCurveName) {
        this.kexType = kexType;
        this.dhPrimeSizeBits = dhPrimeSizeBits;
        this.ecCurveId = ecCurveId;
        this.ecCurveName = ecCurveName;
    }

    /**
     * Parse a ServerKeyExchange message.
     * @param data The raw ServerKeyExchange body
     * @param cipherSuite The negotiated cipher suite from ServerHello
     * @return Parsed key exchange parameters
     */
    public static ServerKeyExchange parse(byte[] data, int cipherSuite) {
        if (data == null || data.length < 3) {
            return new ServerKeyExchange(KexType.UNKNOWN, 0, 0, null);
        }

        if (isECDHECipher(cipherSuite)) {
            return parseECDHE(data);
        } else if (isDHECipher(cipherSuite)) {
            return parseDHE(data);
        }
        return new ServerKeyExchange(KexType.UNKNOWN, 0, 0, null);
    }

    private static ServerKeyExchange parseDHE(byte[] data) {
        int ptr = 0;
        if (ptr + 2 > data.length) {
            return new ServerKeyExchange(KexType.DHE, 0, 0, null);
        }
        // dh_p length (2 bytes) + prime bytes
        int pLen = TlsRecordLayer.dec16be(data, ptr);
        ptr += 2;
        if (ptr + pLen > data.length) {
            return new ServerKeyExchange(KexType.DHE, 0, 0, null);
        }

        // Count significant bits in prime, skipping leading zeros
        int primeBits = 0;
        for (int i = 0; i < pLen; i++) {
            int b = data[ptr + i] & 0xFF;
            if (b == 0 && primeBits == 0) continue;
            if (primeBits == 0) {
                // First non-zero byte: count leading bits
                primeBits = (pLen - i - 1) * 8;
                primeBits += 32 - Integer.numberOfLeadingZeros(b);
                break;
            }
        }
        if (primeBits == 0) primeBits = pLen * 8;

        return new ServerKeyExchange(KexType.DHE, primeBits, 0, null);
    }

    private static ServerKeyExchange parseECDHE(byte[] data) {
        if (data.length < 3) {
            return new ServerKeyExchange(KexType.ECDHE, 0, 0, null);
        }
        int curveType = data[0] & 0xFF;
        if (curveType != 3) { // 3 = named_curve
            return new ServerKeyExchange(KexType.ECDHE, 0, 0, null);
        }
        int curveId = TlsRecordLayer.dec16be(data, 1);
        String curveName = (curveId >= 0 && curveId < NAMED_CURVES.length)
                ? NAMED_CURVES[curveId] : null;
        if (curveName == null) {
            curveName = "unknown_curve_0x" + Integer.toHexString(curveId);
        }
        return new ServerKeyExchange(KexType.ECDHE, 0, curveId, curveName);
    }

    /** Check if cipher suite uses ECDHE key exchange. */
    private static boolean isECDHECipher(int cs) {
        // TLS_ECDHE_* cipher suites: 0xC007-0xC02F (major range)
        // Also includes some later ECDHE suites
        return (cs >= 0xC007 && cs <= 0xC02F)
                || (cs >= 0xCCA8 && cs <= 0xCCAC);
    }

    /** Check if cipher suite uses DHE key exchange. */
    private static boolean isDHECipher(int cs) {
        // TLS_DHE_* cipher suites
        return (cs >= 0x0033 && cs <= 0x009F && !isRSAOnlyCipher(cs));
    }

    /** Check if cipher suite is RSA-only (no DHE). */
    private static boolean isRSAOnlyCipher(int cs) {
        // Common RSA key exchange suites in the 0x0033-0x009F range
        return cs == 0x002F || cs == 0x0035 || cs == 0x003C || cs == 0x003D
                || cs == 0x009C || cs == 0x009D;
    }

    public KexType getKexType() { return kexType; }
    public int getDhPrimeSizeBits() { return dhPrimeSizeBits; }
    public int getEcCurveId() { return ecCurveId; }
    public String getEcCurveName() { return ecCurveName; }
}
