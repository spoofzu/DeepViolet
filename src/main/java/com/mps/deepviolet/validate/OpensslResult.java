package com.mps.deepviolet.validate;

import java.util.ArrayList;
import java.util.List;

/**
 * Parsed results from running openssl s_client and x509 commands against a host.
 */
public class OpensslResult {

    /** Creates an empty result. */
    OpensslResult() {}

    String opensslVersion;
    boolean connectionSucceeded;
    String connectionError;
    String negotiatedProtocol;
    String negotiatedCipher;
    int chainLength;
    boolean ocspStaplingPresent;
    List<CertInfo> certificates = new ArrayList<>();

    /**
     * Parsed certificate information from openssl x509 -text output.
     */
    static class CertInfo {
        String subjectDN;
        String issuerDN;
        String serialNumber;
        int version;
        String signingAlgorithm;
        String publicKeyAlgorithm;
        int publicKeySize;
        String publicKeyCurve;
        String notValidBefore;
        String notValidAfter;
        boolean selfSigned;
        List<String> sans = new ArrayList<>();
        String sha256Fingerprint;
    }
}
