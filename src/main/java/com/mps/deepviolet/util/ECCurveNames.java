package com.mps.deepviolet.util;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Static lookup table for EC curve names to replace Bouncy Castle's ECNamedCurveTable.
 * Supports common NIST, SEC, and Brainpool curves.
 *
 * @author Milton Smith
 */
public class ECCurveNames {

    /**
     * Map of curve order (n) to curve name. Order is used as the primary
     * identifier since it uniquely identifies a curve among common curves.
     */
    private static final Map<BigInteger, String> CURVE_BY_ORDER = new LinkedHashMap<>();

    /**
     * Map of (field size + cofactor) to curve name as secondary lookup.
     */
    private static final Map<String, String> CURVE_BY_PARAMS = new LinkedHashMap<>();

    static {
        // NIST / SEC curves (most common)
        // secp256r1 (P-256) - order
        CURVE_BY_ORDER.put(
            new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16),
            "secp256r1");

        // secp384r1 (P-384) - order
        CURVE_BY_ORDER.put(
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
            "secp384r1");

        // secp521r1 (P-521) - order
        CURVE_BY_ORDER.put(
            new BigInteger("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
            "secp521r1");

        // secp256k1 (Bitcoin curve) - order
        CURVE_BY_ORDER.put(
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),
            "secp256k1");

        // secp224r1 (P-224) - order
        CURVE_BY_ORDER.put(
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 16),
            "secp224r1");

        // secp192r1 (P-192) - order
        CURVE_BY_ORDER.put(
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16),
            "secp192r1");

        // Brainpool curves
        // brainpoolP256r1 - order
        CURVE_BY_ORDER.put(
            new BigInteger("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16),
            "brainpoolP256r1");

        // brainpoolP384r1 - order
        CURVE_BY_ORDER.put(
            new BigInteger("8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565", 16),
            "brainpoolP384r1");

        // brainpoolP512r1 - order
        CURVE_BY_ORDER.put(
            new BigInteger("AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069", 16),
            "brainpoolP512r1");

        // Secondary lookup by field size and cofactor
        CURVE_BY_PARAMS.put("256-1", "secp256r1");
        CURVE_BY_PARAMS.put("384-1", "secp384r1");
        CURVE_BY_PARAMS.put("521-1", "secp521r1");
        CURVE_BY_PARAMS.put("224-1", "secp224r1");
        CURVE_BY_PARAMS.put("192-1", "secp192r1");
    }

    private ECCurveNames() {}

    /**
     * Look up the curve name for a given ECParameterSpec.
     *
     * @param spec The EC parameter specification
     * @return The curve name (e.g., "secp256r1"), or "unknown" if not found
     */
    public static String lookupCurveName(ECParameterSpec spec) {
        if (spec == null) {
            return "unknown";
        }

        // Primary lookup: by curve order
        BigInteger order = spec.getOrder();
        if (order != null) {
            String name = CURVE_BY_ORDER.get(order);
            if (name != null) {
                return name;
            }
        }

        // Secondary lookup: by field size and cofactor
        int fieldSize = spec.getOrder().bitLength();
        int cofactor = spec.getCofactor();
        String key = fieldSize + "-" + cofactor;
        String name = CURVE_BY_PARAMS.get(key);
        if (name != null) {
            return name;
        }

        // Try to get name via JDK's AlgorithmParameters
        try {
            // Common curve names to try
            String[] curveNames = {
                "secp256r1", "secp384r1", "secp521r1", "secp256k1",
                "secp224r1", "secp192r1", "prime256v1", "prime192v1",
                "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"
            };

            for (String curveName : curveNames) {
                try {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
                    params.init(new ECGenParameterSpec(curveName));
                    ECParameterSpec namedSpec = params.getParameterSpec(ECParameterSpec.class);
                    if (matchesSpec(spec, namedSpec)) {
                        return curveName;
                    }
                } catch (Exception ignored) {
                    // Curve not supported by this JDK
                }
            }
        } catch (Exception ignored) {
            // Fall through to unknown
        }

        return "unknown";
    }

    /**
     * Check if two ECParameterSpecs match by comparing their orders.
     */
    private static boolean matchesSpec(ECParameterSpec spec1, ECParameterSpec spec2) {
        if (spec1 == null || spec2 == null) {
            return false;
        }
        // Compare order and cofactor
        return spec1.getOrder().equals(spec2.getOrder())
            && spec1.getCofactor() == spec2.getCofactor();
    }

    /**
     * Get the bit length for a named curve.
     *
     * @param curveName The curve name
     * @return The bit length, or -1 if unknown
     */
    public static int getCurveBitLength(String curveName) {
        if (curveName == null) {
            return -1;
        }
        switch (curveName.toLowerCase()) {
            case "secp192r1":
            case "prime192v1":
                return 192;
            case "secp224r1":
                return 224;
            case "secp256r1":
            case "secp256k1":
            case "prime256v1":
            case "brainpoolp256r1":
                return 256;
            case "secp384r1":
            case "brainpoolp384r1":
                return 384;
            case "secp521r1":
            case "brainpoolp512r1":
                return 521;
            default:
                return -1;
        }
    }

    /**
     * Get the recommended curve name alias (NIST name if applicable).
     *
     * @param curveName The curve name
     * @return The alias, or the original name if no alias exists
     */
    public static String getCurveAlias(String curveName) {
        if (curveName == null) {
            return null;
        }
        switch (curveName.toLowerCase()) {
            case "prime256v1":
                return "secp256r1";
            case "prime192v1":
                return "secp192r1";
            default:
                return curveName;
        }
    }
}
