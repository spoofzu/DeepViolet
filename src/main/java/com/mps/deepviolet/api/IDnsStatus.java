package com.mps.deepviolet.api;

/**
 * DNS security status for a host.
 * Provides information about CAA records and DANE/TLSA records.
 */
public interface IDnsStatus {

    /**
     * Whether DNS security checks were successfully performed.
     * @return true if DNS queries completed successfully
     */
    boolean isAvailable();

    /**
     * Whether CAA (Certificate Authority Authorization) records exist for the host.
     * CAA records restrict which CAs can issue certificates for a domain.
     * @return true if CAA records are present
     */
    boolean hasCaaRecords();

    /**
     * Whether DANE/TLSA records exist for the host.
     * TLSA records bind certificates to DNS names using DNSSEC.
     * @return true if TLSA records are present
     */
    boolean hasTlsaRecords();
}
