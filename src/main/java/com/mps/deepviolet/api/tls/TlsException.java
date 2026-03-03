package com.mps.deepviolet.api.tls;

/**
 * TLS-specific exception for TlsSocket operations.
 * Thrown when TLS handshake parsing or protocol errors occur.
 */
public class TlsException extends Exception {

    private static final long serialVersionUID = 1L;

    /** Alert level from TLS alert message, if applicable */
    private int alertLevel = -1;

    /** Alert description from TLS alert message, if applicable */
    private int alertDescription = -1;

    public TlsException(String message) {
        super(message);
    }

    public TlsException(String message, Throwable cause) {
        super(message, cause);
    }

    public TlsException(Throwable cause) {
        super(cause);
    }

    /**
     * Create exception from TLS alert message.
     * @param alertLevel The alert level (1 = warning, 2 = fatal)
     * @param alertDescription The alert description code
     */
    public TlsException(int alertLevel, int alertDescription) {
        super(formatAlertMessage(alertLevel, alertDescription));
        this.alertLevel = alertLevel;
        this.alertDescription = alertDescription;
    }

    /**
     * Create exception from TLS alert message with custom message.
     * @param message Additional context
     * @param alertLevel The alert level (1 = warning, 2 = fatal)
     * @param alertDescription The alert description code
     */
    public TlsException(String message, int alertLevel, int alertDescription) {
        super(message + ": " + formatAlertMessage(alertLevel, alertDescription));
        this.alertLevel = alertLevel;
        this.alertDescription = alertDescription;
    }

    public int getAlertLevel() {
        return alertLevel;
    }

    public int getAlertDescription() {
        return alertDescription;
    }

    public boolean isAlertException() {
        return alertLevel >= 0 && alertDescription >= 0;
    }

    public boolean isFatalAlert() {
        return alertLevel == 2;
    }

    private static String formatAlertMessage(int level, int description) {
        String levelStr = (level == 1) ? "warning" : (level == 2) ? "fatal" : "unknown";
        return String.format("TLS alert: level=%s(%d), description=%s(%d)",
                levelStr, level, getAlertDescriptionName(description), description);
    }

    /**
     * Get human-readable name for TLS alert description code.
     */
    public static String getAlertDescriptionName(int description) {
        switch (description) {
            case 0: return "close_notify";
            case 10: return "unexpected_message";
            case 20: return "bad_record_mac";
            case 21: return "decryption_failed";
            case 22: return "record_overflow";
            case 30: return "decompression_failure";
            case 40: return "handshake_failure";
            case 41: return "no_certificate";
            case 42: return "bad_certificate";
            case 43: return "unsupported_certificate";
            case 44: return "certificate_revoked";
            case 45: return "certificate_expired";
            case 46: return "certificate_unknown";
            case 47: return "illegal_parameter";
            case 48: return "unknown_ca";
            case 49: return "access_denied";
            case 50: return "decode_error";
            case 51: return "decrypt_error";
            case 60: return "export_restriction";
            case 70: return "protocol_version";
            case 71: return "insufficient_security";
            case 80: return "internal_error";
            case 86: return "inappropriate_fallback";
            case 90: return "user_canceled";
            case 100: return "no_renegotiation";
            case 109: return "missing_extension";
            case 110: return "unsupported_extension";
            case 111: return "certificate_unobtainable";
            case 112: return "unrecognized_name";
            case 113: return "bad_certificate_status_response";
            case 114: return "bad_certificate_hash_value";
            case 115: return "unknown_psk_identity";
            case 116: return "certificate_required";
            case 120: return "no_application_protocol";
            default: return "unknown";
        }
    }
}
