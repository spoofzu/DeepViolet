package com.mps.deepviolet.api;

/**
 * Implementation of IDnsStatus.
 */
class DnsStatus implements IDnsStatus {

    private final boolean available;
    private final boolean hasCaaRecords;
    private final boolean hasTlsaRecords;

    DnsStatus(boolean available, boolean hasCaaRecords, boolean hasTlsaRecords) {
        this.available = available;
        this.hasCaaRecords = hasCaaRecords;
        this.hasTlsaRecords = hasTlsaRecords;
    }

    /** Create an unavailable status (DNS check failed). */
    static DnsStatus unavailable() {
        return new DnsStatus(false, false, false);
    }

    @Override
    public boolean isAvailable() { return available; }

    @Override
    public boolean hasCaaRecords() { return hasCaaRecords; }

    @Override
    public boolean hasTlsaRecords() { return hasTlsaRecords; }
}
