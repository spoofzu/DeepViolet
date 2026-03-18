package com.mps.deepviolet.validate;

import java.util.ArrayList;
import java.util.List;

/**
 * Structured result of comparing DV API output against openssl for one host.
 */
public class ComparisonResult {

    /** Creates an empty ComparisonResult. */
    ComparisonResult() {}

    String host;
    int port;
    String opensslVersion;
    boolean dvSessionSucceeded;
    String dvSessionError;
    List<FieldComparison> fields = new ArrayList<>();
    boolean allMatched;
    int matchCount;
    int mismatchCount;
    int totalFields;
    OpensslResult opensslData;

    /**
     * Comparison of a single field between DV API and openssl.
     */
    static class FieldComparison {
        String section;
        String field;
        String dvValue;
        String opensslValue;
        boolean matched;

        FieldComparison(String section, String field, String dvValue, String opensslValue, boolean matched) {
            this.section = section;
            this.field = field;
            this.dvValue = dvValue;
            this.opensslValue = opensslValue;
            this.matched = matched;
        }
    }

    /** Check whether all compared fields matched between DV API and openssl.
     * @return true if all compared fields matched */
    public boolean isAllMatched() {
        return allMatched;
    }

    /** Check whether the DV API session was successfully established.
     * @return true if the DV API session was successfully established */
    public boolean isDvSessionSucceeded() {
        return dvSessionSucceeded;
    }

    void computeSummary() {
        matchCount = 0;
        mismatchCount = 0;
        for (FieldComparison fc : fields) {
            if (fc.matched) {
                matchCount++;
            } else {
                mismatchCount++;
            }
        }
        totalFields = fields.size();
        allMatched = mismatchCount == 0;
    }
}
