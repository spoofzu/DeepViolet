package com.mps.deepviolet.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Lightweight ASN.1 DER parser to replace Bouncy Castle dependencies.
 * Supports parsing common DER structures used in X.509 certificates.
 *
 * @author Milton Smith
 */
public class DerParser {

    // ASN.1 Tag classes
    public static final int TAG_CLASS_UNIVERSAL = 0x00;
    public static final int TAG_CLASS_APPLICATION = 0x40;
    public static final int TAG_CLASS_CONTEXT = 0x80;
    public static final int TAG_CLASS_PRIVATE = 0xC0;

    // Common ASN.1 Universal tags
    public static final int TAG_BOOLEAN = 0x01;
    public static final int TAG_INTEGER = 0x02;
    public static final int TAG_BIT_STRING = 0x03;
    public static final int TAG_OCTET_STRING = 0x04;
    public static final int TAG_NULL = 0x05;
    public static final int TAG_OBJECT_IDENTIFIER = 0x06;
    public static final int TAG_ENUMERATED = 0x0A;
    public static final int TAG_UTF8_STRING = 0x0C;
    public static final int TAG_PRINTABLE_STRING = 0x13;
    public static final int TAG_IA5_STRING = 0x16;
    public static final int TAG_UTC_TIME = 0x17;
    public static final int TAG_GENERALIZED_TIME = 0x18;
    public static final int TAG_VISIBLE_STRING = 0x1A;
    public static final int TAG_SEQUENCE = 0x30;
    public static final int TAG_SET = 0x31;

    private DerParser() {}

    /**
     * Parse DER-encoded data from a byte array.
     * @param data The DER-encoded byte array
     * @return A DerValue representing the parsed data
     * @throws IOException If parsing fails
     */
    public static DerValue parse(byte[] data) throws IOException {
        return parse(new ByteArrayInputStream(data));
    }

    /**
     * Parse DER-encoded data from an input stream.
     * @param is The input stream containing DER-encoded data
     * @return A DerValue representing the parsed data
     * @throws IOException If parsing fails
     */
    public static DerValue parse(InputStream is) throws IOException {
        int tag = is.read();
        if (tag == -1) {
            throw new IOException("Unexpected end of stream while reading tag");
        }

        int length = readLength(is);
        byte[] value = new byte[length];
        int bytesRead = 0;
        while (bytesRead < length) {
            int r = is.read(value, bytesRead, length - bytesRead);
            if (r == -1) {
                throw new IOException("Unexpected end of stream while reading value");
            }
            bytesRead += r;
        }

        return new DerValue(tag, value);
    }

    /**
     * Parse all DER values from a byte array (for sequences with multiple elements).
     * @param data The DER-encoded byte array
     * @return List of DerValues
     * @throws IOException If parsing fails
     */
    public static List<DerValue> parseAll(byte[] data) throws IOException {
        List<DerValue> values = new ArrayList<>();
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        while (bis.available() > 0) {
            values.add(parse(bis));
        }
        return values;
    }

    /**
     * Read the length field from DER encoding.
     */
    private static int readLength(InputStream is) throws IOException {
        int b = is.read();
        if (b == -1) {
            throw new IOException("Unexpected end of stream while reading length");
        }

        if ((b & 0x80) == 0) {
            // Short form: length is in the low 7 bits
            return b;
        }

        // Long form: low 7 bits indicate number of length bytes
        int numBytes = b & 0x7F;
        if (numBytes == 0) {
            throw new IOException("Indefinite length not supported");
        }
        if (numBytes > 4) {
            throw new IOException("Length too long: " + numBytes + " bytes");
        }

        int length = 0;
        for (int i = 0; i < numBytes; i++) {
            b = is.read();
            if (b == -1) {
                throw new IOException("Unexpected end of stream while reading length bytes");
            }
            length = (length << 8) | b;
        }

        return length;
    }

    /**
     * Represents a parsed DER value with its tag and content.
     */
    public static class DerValue {
        private final int tag;
        private final byte[] value;

        public DerValue(int tag, byte[] value) {
            this.tag = tag;
            this.value = value;
        }

        /**
         * Get the ASN.1 tag.
         */
        public int getTag() {
            return tag;
        }

        /**
         * Get the tag number (stripped of class and constructed bits).
         */
        public int getTagNumber() {
            return tag & 0x1F;
        }

        /**
         * Check if this is a constructed type (SEQUENCE, SET, etc).
         */
        public boolean isConstructed() {
            return (tag & 0x20) != 0;
        }

        /**
         * Check if this is a context-specific tagged value.
         */
        public boolean isContextSpecific() {
            return (tag & 0xC0) == TAG_CLASS_CONTEXT;
        }

        /**
         * Get the context-specific tag number (0-31).
         */
        public int getContextTag() {
            if (!isContextSpecific()) {
                throw new IllegalStateException("Not a context-specific tag");
            }
            return tag & 0x1F;
        }

        /**
         * Get the raw value bytes.
         */
        public byte[] getValue() {
            return value;
        }

        /**
         * Get the length of the value.
         */
        public int getLength() {
            return value.length;
        }

        /**
         * Parse this value as a SEQUENCE and return its elements.
         */
        public List<DerValue> getSequence() throws IOException {
            if (tag != TAG_SEQUENCE && !isConstructed()) {
                throw new IOException("Expected SEQUENCE, got tag: " + tag);
            }
            return parseAll(value);
        }

        /**
         * Parse this value as a SET and return its elements.
         */
        public List<DerValue> getSet() throws IOException {
            if (tag != TAG_SET && !isConstructed()) {
                throw new IOException("Expected SET, got tag: " + tag);
            }
            return parseAll(value);
        }

        /**
         * Get this value as an OCTET STRING.
         */
        public byte[] getOctetString() throws IOException {
            if (tag != TAG_OCTET_STRING) {
                throw new IOException("Expected OCTET STRING, got tag: " + tag);
            }
            return value;
        }

        /**
         * Get this value as a BIT STRING.
         * Returns the bit string content (excluding the unused bits indicator).
         */
        public byte[] getBitString() throws IOException {
            if (tag != TAG_BIT_STRING) {
                throw new IOException("Expected BIT STRING, got tag: " + tag);
            }
            if (value.length == 0) {
                return new byte[0];
            }
            // First byte indicates unused bits in the last byte
            int unusedBits = value[0] & 0xFF;
            byte[] result = new byte[value.length - 1];
            System.arraycopy(value, 1, result, 0, result.length);
            return result;
        }

        /**
         * Get the BIT STRING as an integer value.
         */
        public int getBitStringAsInt() throws IOException {
            byte[] bits = getBitString();
            int result = 0;
            for (int i = 0; i < bits.length && i < 4; i++) {
                result |= (bits[i] & 0xFF) << (i * 8);
            }
            return result;
        }

        /**
         * Get this value as an IA5String.
         */
        public String getIA5String() throws IOException {
            if (tag != TAG_IA5_STRING) {
                throw new IOException("Expected IA5String, got tag: " + tag);
            }
            return new String(value, StandardCharsets.US_ASCII);
        }

        /**
         * Get this value as a UTF8String.
         */
        public String getUTF8String() throws IOException {
            if (tag != TAG_UTF8_STRING) {
                throw new IOException("Expected UTF8String, got tag: " + tag);
            }
            return new String(value, StandardCharsets.UTF_8);
        }

        /**
         * Get this value as a PrintableString.
         */
        public String getPrintableString() throws IOException {
            if (tag != TAG_PRINTABLE_STRING) {
                throw new IOException("Expected PrintableString, got tag: " + tag);
            }
            return new String(value, StandardCharsets.US_ASCII);
        }

        /**
         * Get this value as a VisibleString.
         */
        public String getVisibleString() throws IOException {
            if (tag != TAG_VISIBLE_STRING) {
                throw new IOException("Expected VisibleString, got tag: " + tag);
            }
            return new String(value, StandardCharsets.US_ASCII);
        }

        /**
         * Get this value as any string type.
         */
        public String getString() throws IOException {
            switch (tag) {
                case TAG_IA5_STRING:
                    return getIA5String();
                case TAG_UTF8_STRING:
                    return getUTF8String();
                case TAG_PRINTABLE_STRING:
                    return getPrintableString();
                case TAG_VISIBLE_STRING:
                    return getVisibleString();
                default:
                    // Try as UTF-8
                    return new String(value, StandardCharsets.UTF_8);
            }
        }

        /**
         * Get this value as an OBJECT IDENTIFIER string (dotted notation).
         */
        public String getObjectIdentifier() throws IOException {
            if (tag != TAG_OBJECT_IDENTIFIER) {
                throw new IOException("Expected OBJECT IDENTIFIER, got tag: " + tag);
            }
            return decodeOid(value);
        }

        /**
         * Get this value as an INTEGER.
         */
        public BigInteger getInteger() throws IOException {
            if (tag != TAG_INTEGER) {
                throw new IOException("Expected INTEGER, got tag: " + tag);
            }
            return new BigInteger(value);
        }

        /**
         * Get this value as an ENUMERATED.
         */
        public BigInteger getEnumerated() throws IOException {
            if (tag != TAG_ENUMERATED) {
                throw new IOException("Expected ENUMERATED, got tag: " + tag);
            }
            return new BigInteger(value);
        }

        /**
         * Get this value as a small integer (handles both INTEGER and ENUMERATED).
         */
        public int getIntValue() throws IOException {
            if (tag == TAG_INTEGER || tag == TAG_ENUMERATED) {
                return new BigInteger(value).intValue();
            }
            throw new IOException("Expected INTEGER or ENUMERATED, got tag: " + tag);
        }

        /**
         * Get this value as a long integer (handles both INTEGER and ENUMERATED).
         */
        public long getLongValue() throws IOException {
            if (tag == TAG_INTEGER || tag == TAG_ENUMERATED) {
                return new BigInteger(value).longValue();
            }
            throw new IOException("Expected INTEGER or ENUMERATED, got tag: " + tag);
        }

        /**
         * Get this value as an ENUMERATED int value.
         */
        public int getEnumValue() throws IOException {
            return getEnumerated().intValue();
        }

        /**
         * Get this value as a BOOLEAN.
         */
        public boolean getBoolean() throws IOException {
            if (tag != TAG_BOOLEAN) {
                throw new IOException("Expected BOOLEAN, got tag: " + tag);
            }
            if (value.length != 1) {
                throw new IOException("Invalid BOOLEAN length: " + value.length);
            }
            return value[0] != 0;
        }

        /**
         * Get the inner content of a context-specific tagged value.
         */
        public DerValue getTaggedObject() throws IOException {
            if (!isContextSpecific()) {
                throw new IOException("Not a context-specific tagged object");
            }
            if (isConstructed()) {
                // Explicit tagging: content is a full TLV
                return parse(value);
            } else {
                // Implicit tagging: content is raw value
                return new DerValue(tag, value);
            }
        }

        /**
         * Get the inner content of a context-specific tagged value as a sequence.
         */
        public List<DerValue> getTaggedSequence() throws IOException {
            if (!isContextSpecific()) {
                throw new IOException("Not a context-specific tagged object");
            }
            return parseAll(value);
        }

        /**
         * Try to get string content from this value, handling various tags.
         * Useful for Subject Alternative Names and other string-like values.
         */
        public String getStringValue() {
            // Handle common string types and context-specific tags
            if (isContextSpecific()) {
                // For context-specific tags (like in GeneralName),
                // try to decode as ASCII/UTF-8
                return new String(value, StandardCharsets.UTF_8);
            }

            switch (tag) {
                case TAG_IA5_STRING:
                case TAG_UTF8_STRING:
                case TAG_PRINTABLE_STRING:
                case TAG_VISIBLE_STRING:
                    return new String(value, StandardCharsets.UTF_8);
                default:
                    return new String(value, StandardCharsets.UTF_8);
            }
        }

        @Override
        public String toString() {
            return "DerValue[tag=0x" + Integer.toHexString(tag) + ", length=" + value.length + "]";
        }
    }

    /**
     * Decode an OID from its DER-encoded bytes.
     */
    private static String decodeOid(byte[] data) {
        if (data.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();

        // First byte encodes first two components: value = 40*X + Y
        int first = data[0] & 0xFF;
        sb.append(first / 40);
        sb.append('.');
        sb.append(first % 40);

        // Remaining bytes encode subsequent components using base-128
        long component = 0;
        for (int i = 1; i < data.length; i++) {
            int b = data[i] & 0xFF;
            component = (component << 7) | (b & 0x7F);
            if ((b & 0x80) == 0) {
                // End of this component
                sb.append('.');
                sb.append(component);
                component = 0;
            }
        }

        return sb.toString();
    }

    /**
     * Encode an OID string to DER bytes.
     */
    public static byte[] encodeOid(String oid) {
        String[] parts = oid.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("OID must have at least 2 components");
        }

        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);

        // Build the encoded bytes
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        baos.write(40 * first + second);

        for (int i = 2; i < parts.length; i++) {
            long val = Long.parseLong(parts[i]);
            encodeBase128(baos, val);
        }

        return baos.toByteArray();
    }

    /**
     * Encode a value in base-128 (for OID components).
     */
    private static void encodeBase128(java.io.ByteArrayOutputStream baos, long value) {
        if (value == 0) {
            baos.write(0);
            return;
        }

        // Count bytes needed
        int numBytes = 0;
        long temp = value;
        while (temp > 0) {
            numBytes++;
            temp >>= 7;
        }

        // Encode in reverse order
        byte[] bytes = new byte[numBytes];
        for (int i = numBytes - 1; i >= 0; i--) {
            bytes[i] = (byte) ((value & 0x7F) | (i < numBytes - 1 ? 0x80 : 0));
            value >>= 7;
        }

        baos.write(bytes, 0, bytes.length);
    }

    /**
     * Convert a byte array to a hex string.
     */
    public static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X", b & 0xFF));
            sb.append(':');
        }
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }
}
