package com.mps.deepviolet.api.tls;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * TLS record layer I/O for reading and writing TLS records.
 * Handles the 5-byte record header (type, version, length) and record payload.
 *
 * This is adapted from the existing CipherSuiteUtil OutputRecord and
 * CipherSuiteUtilInputRecord classes but consolidated into a single class.
 */
public class TlsRecordLayer {

    /** TLS record type: ChangeCipherSpec. */
    public static final int CHANGE_CIPHER_SPEC = 20;
    /** TLS record type: Alert. */
    public static final int ALERT = 21;
    /** TLS record type: Handshake. */
    public static final int HANDSHAKE = 22;
    /** TLS record type: ApplicationData. */
    public static final int APPLICATION_DATA = 23;

    /** Maximum TLS record payload length per specification. */
    public static final int MAX_RECORD_LEN = 16384;

    /** Handshake message type: ClientHello. */
    public static final int HANDSHAKE_CLIENT_HELLO = 1;
    /** Handshake message type: ServerHello. */
    public static final int HANDSHAKE_SERVER_HELLO = 2;
    /** Handshake message type: NewSessionTicket. */
    public static final int HANDSHAKE_NEW_SESSION_TICKET = 4;
    /** Handshake message type: EndOfEarlyData. */
    public static final int HANDSHAKE_END_OF_EARLY_DATA = 5;
    /** Handshake message type: EncryptedExtensions. */
    public static final int HANDSHAKE_ENCRYPTED_EXTENSIONS = 8;
    /** Handshake message type: Certificate. */
    public static final int HANDSHAKE_CERTIFICATE = 11;
    /** Handshake message type: ServerKeyExchange. */
    public static final int HANDSHAKE_SERVER_KEY_EXCHANGE = 12;
    /** Handshake message type: CertificateRequest. */
    public static final int HANDSHAKE_CERTIFICATE_REQUEST = 13;
    /** Handshake message type: ServerHelloDone. */
    public static final int HANDSHAKE_SERVER_HELLO_DONE = 14;
    /** Handshake message type: CertificateVerify. */
    public static final int HANDSHAKE_CERTIFICATE_VERIFY = 15;
    /** Handshake message type: ClientKeyExchange. */
    public static final int HANDSHAKE_CLIENT_KEY_EXCHANGE = 16;
    /** Handshake message type: Finished. */
    public static final int HANDSHAKE_FINISHED = 20;
    /** Handshake message type: CertificateStatus. */
    public static final int HANDSHAKE_CERTIFICATE_STATUS = 22;
    /** Handshake message type: KeyUpdate. */
    public static final int HANDSHAKE_KEY_UPDATE = 24;
    /** Handshake message type: MessageHash. */
    public static final int HANDSHAKE_MESSAGE_HASH = 254;

    private final InputStream input;
    private final OutputStream output;

    // Output buffer for writing records
    private byte[] outputBuffer = new byte[MAX_RECORD_LEN + 5];
    private int outputPtr = 5; // Start after header
    private int outputVersion;
    private int outputType;

    // Input buffer for reading records
    private byte[] inputBuffer = new byte[MAX_RECORD_LEN + 5];
    private int inputPtr = 0;
    private int inputEnd = 0;
    private int inputVersion;
    private int inputType;
    private int expectedType = -1;
    private byte[] lastRecordHeader;

    /** Create a TLS record layer over the given streams.
     *  @param input the input stream
     *  @param output the output stream */
    public TlsRecordLayer(InputStream input, OutputStream output) {
        this.input = input;
        this.output = output;
    }

    // ==================== Output Methods ====================

    /**
     * Set the record type for output.
     * @param type TLS record type
     */
    public void setOutputType(int type) {
        this.outputType = type;
    }

    /**
     * Set the protocol version for output records.
     * @param version TLS version code
     */
    public void setOutputVersion(int version) {
        this.outputVersion = version;
    }

    /**
     * Write a byte to the output buffer.
     * @param b byte value to write
     * @throws IOException on I/O errors
     */
    public void write(int b) throws IOException {
        outputBuffer[outputPtr++] = (byte) b;
        if (outputPtr == outputBuffer.length) {
            flushOutput();
        }
    }

    /**
     * Write bytes to the output buffer.
     * @param buf byte array to write
     * @throws IOException on I/O errors
     */
    public void write(byte[] buf) throws IOException {
        write(buf, 0, buf.length);
    }

    /**
     * Write bytes to the output buffer.
     * @param buf source byte array
     * @param off start offset in buf
     * @param len number of bytes to write
     * @throws IOException on I/O errors
     */
    public void write(byte[] buf, int off, int len) throws IOException {
        while (len > 0) {
            int clen = Math.min(outputBuffer.length - outputPtr, len);
            System.arraycopy(buf, off, outputBuffer, outputPtr, clen);
            outputPtr += clen;
            off += clen;
            len -= clen;
            if (outputPtr == outputBuffer.length) {
                flushOutput();
            }
        }
    }

    /**
     * Flush the output buffer, writing a complete record.
     * @throws IOException on I/O errors
     */
    public void flushOutput() throws IOException {
        outputBuffer[0] = (byte) outputType;
        enc16be(outputVersion, outputBuffer, 1);
        enc16be(outputPtr - 5, outputBuffer, 3);
        output.write(outputBuffer, 0, outputPtr);
        output.flush();
        outputPtr = 5;
    }

    // ==================== Input Methods ====================

    /**
     * Set the expected record type for input. Alert records are still processed.
     * @param expectedType expected TLS record type, or -1 for any
     */
    public void setExpectedType(int expectedType) {
        this.expectedType = expectedType;
    }

    /**
     * Get the version from the last read record.
     * @return input record version
     */
    public int getInputVersion() {
        return inputVersion;
    }

    /**
     * Get the type of the last read record.
     * @return input record type
     */
    public int getInputType() {
        return inputType;
    }

    /**
     * Read a single byte from the input.
     * @return the byte value (0-255)
     * @throws IOException on I/O errors
     * @throws TlsException on TLS protocol errors
     */
    public int read() throws IOException, TlsException {
        while (inputPtr == inputEnd) {
            refillInput();
        }
        return inputBuffer[inputPtr++] & 0xFF;
    }

    /**
     * Read bytes from the input.
     * @param buf destination buffer
     * @param off start offset in buf
     * @param len maximum bytes to read
     * @return number of bytes read
     * @throws IOException on I/O errors
     * @throws TlsException on TLS protocol errors
     */
    public int read(byte[] buf, int off, int len) throws IOException, TlsException {
        while (inputPtr == inputEnd) {
            refillInput();
        }
        int clen = Math.min(inputEnd - inputPtr, len);
        System.arraycopy(inputBuffer, inputPtr, buf, off, clen);
        inputPtr += clen;
        return clen;
    }

    /**
     * Read exactly len bytes from the input.
     * @param buf destination buffer
     * @throws IOException on I/O errors
     * @throws TlsException on TLS protocol errors
     */
    public void readFully(byte[] buf) throws IOException, TlsException {
        readFully(buf, 0, buf.length);
    }

    /**
     * Read exactly len bytes from the input.
     * @param buf destination buffer
     * @param off start offset in buf
     * @param len exact number of bytes to read
     * @throws IOException on I/O errors
     * @throws TlsException on TLS protocol errors
     */
    public void readFully(byte[] buf, int off, int len) throws IOException, TlsException {
        while (len > 0) {
            int rlen = read(buf, off, len);
            if (rlen < 0) {
                throw new EOFException();
            }
            off += rlen;
            len -= rlen;
        }
    }

    /**
     * Read the next record from the input stream.
     */
    private void refillInput() throws IOException, TlsException {
        for (;;) {
            // Read 5-byte header
            readFullyFromStream(input, inputBuffer, 0, 5);
            inputType = inputBuffer[0] & 0xFF;
            inputVersion = dec16be(inputBuffer, 1);
            inputEnd = dec16be(inputBuffer, 3);

            if (inputEnd > MAX_RECORD_LEN) {
                throw new TlsException("Record too large: " + inputEnd);
            }

            // Read payload
            readFullyFromStream(input, inputBuffer, 0, inputEnd);
            inputPtr = 0;

            // Handle alerts
            if (inputType == ALERT) {
                if (inputEnd >= 2) {
                    int alertLevel = inputBuffer[0] & 0xFF;
                    int alertDesc = inputBuffer[1] & 0xFF;
                    // Close notify is a normal termination
                    if (alertDesc == 0) {
                        throw new EOFException("Connection closed by peer");
                    }
                    throw new TlsException(alertLevel, alertDesc);
                }
                // Malformed alert, continue
                continue;
            }

            // Check expected type
            if (expectedType >= 0 && inputType != expectedType) {
                throw new TlsException("Unexpected record type: got " + inputType
                        + ", expected " + expectedType);
            }

            return;
        }
    }

    /**
     * Read a complete TLS record and return the payload.
     * Does NOT consume the record from the input buffer.
     * @return Record payload bytes
     * @throws IOException on I/O errors
     * @throws TlsException on TLS protocol errors
     */
    public byte[] readRecord() throws IOException, TlsException {
        // Read 5-byte header
        byte[] header = new byte[5];
        readFullyFromStream(input, header, 0, 5);
        lastRecordHeader = header;
        inputType = header[0] & 0xFF;
        inputVersion = dec16be(header, 1);
        int length = dec16be(header, 3);

        if (length > MAX_RECORD_LEN) {
            throw new TlsException("Record too large: " + length);
        }

        // Read payload
        byte[] payload = new byte[length];
        readFullyFromStream(input, payload, 0, length);

        // Handle alerts
        if (inputType == ALERT && length >= 2) {
            int alertLevel = payload[0] & 0xFF;
            int alertDesc = payload[1] & 0xFF;
            if (alertDesc == 0) {
                throw new EOFException("Connection closed by peer");
            }
            throw new TlsException(alertLevel, alertDesc);
        }

        return payload;
    }

    /**
     * Read a handshake message. Returns the message type and full message bytes.
     * @return HandshakeMessage containing type and data
     * @throws IOException on I/O errors
     * @throws TlsException on TLS protocol errors
     */
    public HandshakeMessage readHandshakeMessage() throws IOException, TlsException {
        setExpectedType(HANDSHAKE);

        // Read 4-byte handshake header: type (1) + length (3)
        byte[] header = new byte[4];
        readFully(header);

        int msgType = header[0] & 0xFF;
        int msgLen = dec24be(header, 1);

        // Read message body
        byte[] body = new byte[msgLen];
        readFully(body);

        return new HandshakeMessage(msgType, body, inputVersion);
    }

    /**
     * Get the 5-byte record header from the last {@link #readRecord()} call.
     * Used for TLS 1.3 AEAD additional authenticated data.
     * @return copy of the record header, or null
     */
    public byte[] getLastRecordHeader() {
        return lastRecordHeader != null ? lastRecordHeader.clone() : null;
    }

    // ==================== Static Utility Methods ====================

    /** Encode 16-bit value big-endian into buffer.
     *  @param val value to encode
     *  @param buf destination buffer
     *  @param off offset in buffer */
    public static void enc16be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >>> 8);
        buf[off + 1] = (byte) val;
    }

    /** Encode 16-bit value big-endian to output stream.
     *  @param val value to encode
     *  @param out output stream */
    public static void enc16be(int val, ByteArrayOutputStream out) {
        out.write(val >>> 8);
        out.write(val);
    }

    /** Encode 24-bit value big-endian into buffer.
     *  @param val value to encode
     *  @param buf destination buffer
     *  @param off offset in buffer */
    public static void enc24be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >>> 16);
        buf[off + 1] = (byte) (val >>> 8);
        buf[off + 2] = (byte) val;
    }

    /** Encode 32-bit value big-endian into buffer.
     *  @param val value to encode
     *  @param buf destination buffer
     *  @param off offset in buffer */
    public static void enc32be(int val, byte[] buf, int off) {
        buf[off] = (byte) (val >>> 24);
        buf[off + 1] = (byte) (val >>> 16);
        buf[off + 2] = (byte) (val >>> 8);
        buf[off + 3] = (byte) val;
    }

    /** Decode 16-bit big-endian value from buffer.
     *  @param buf source buffer
     *  @param off offset in buffer
     *  @return decoded value */
    public static int dec16be(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    /** Decode 24-bit big-endian value from buffer.
     *  @param buf source buffer
     *  @param off offset in buffer
     *  @return decoded value */
    public static int dec24be(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 16)
                | ((buf[off + 1] & 0xFF) << 8)
                | (buf[off + 2] & 0xFF);
    }

    /** Decode 32-bit big-endian value from buffer.
     *  @param buf source buffer
     *  @param off offset in buffer
     *  @return decoded value */
    public static int dec32be(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 24)
                | ((buf[off + 1] & 0xFF) << 16)
                | ((buf[off + 2] & 0xFF) << 8)
                | (buf[off + 3] & 0xFF);
    }

    /** Read exactly len bytes from the stream.
     *  @param in input stream
     *  @param buf destination buffer
     *  @param off offset in buffer
     *  @param len bytes to read
     *  @throws IOException on I/O errors or EOF */
    public static void readFullyFromStream(InputStream in, byte[] buf, int off, int len)
            throws IOException {
        while (len > 0) {
            int rlen = in.read(buf, off, len);
            if (rlen < 0) {
                throw new EOFException();
            }
            off += rlen;
            len -= rlen;
        }
    }

    /**
     * Get human-readable name for handshake message type.
     * @param type handshake message type code
     * @return human-readable name
     */
    public static String getHandshakeTypeName(int type) {
        switch (type) {
            case HANDSHAKE_CLIENT_HELLO: return "ClientHello";
            case HANDSHAKE_SERVER_HELLO: return "ServerHello";
            case HANDSHAKE_NEW_SESSION_TICKET: return "NewSessionTicket";
            case HANDSHAKE_END_OF_EARLY_DATA: return "EndOfEarlyData";
            case HANDSHAKE_ENCRYPTED_EXTENSIONS: return "EncryptedExtensions";
            case HANDSHAKE_CERTIFICATE: return "Certificate";
            case HANDSHAKE_SERVER_KEY_EXCHANGE: return "ServerKeyExchange";
            case HANDSHAKE_CERTIFICATE_REQUEST: return "CertificateRequest";
            case HANDSHAKE_SERVER_HELLO_DONE: return "ServerHelloDone";
            case HANDSHAKE_CERTIFICATE_VERIFY: return "CertificateVerify";
            case HANDSHAKE_CLIENT_KEY_EXCHANGE: return "ClientKeyExchange";
            case HANDSHAKE_FINISHED: return "Finished";
            case HANDSHAKE_CERTIFICATE_STATUS: return "CertificateStatus";
            case HANDSHAKE_KEY_UPDATE: return "KeyUpdate";
            case HANDSHAKE_MESSAGE_HASH: return "MessageHash";
            default: return String.format("Unknown(%d)", type);
        }
    }

    /**
     * Get human-readable name for record type.
     * @param type TLS record type code
     * @return human-readable name
     */
    public static String getRecordTypeName(int type) {
        switch (type) {
            case CHANGE_CIPHER_SPEC: return "ChangeCipherSpec";
            case ALERT: return "Alert";
            case HANDSHAKE: return "Handshake";
            case APPLICATION_DATA: return "ApplicationData";
            default: return String.format("Unknown(%d)", type);
        }
    }

    /**
     * Container for a handshake message.
     */
    public static class HandshakeMessage {
        private final int type;
        private final byte[] data;
        private final int recordVersion;

        /** Create a handshake message.
         *  @param type handshake type code
         *  @param data message body
         *  @param recordVersion record layer version */
        public HandshakeMessage(int type, byte[] data, int recordVersion) {
            this.type = type;
            this.data = data;
            this.recordVersion = recordVersion;
        }

        /** Returns the handshake type code.
         *  @return type code */
        public int getType() {
            return type;
        }

        /** Returns the message body.
         *  @return message data */
        public byte[] getData() {
            return data;
        }

        /** Returns the record layer version.
         *  @return record version */
        public int getRecordVersion() {
            return recordVersion;
        }

        /** Returns the human-readable type name.
         *  @return type name */
        public String getTypeName() {
            return getHandshakeTypeName(type);
        }

        @Override
        public String toString() {
            return String.format("HandshakeMessage[type=%s(%d), length=%d]",
                    getTypeName(), type, data.length);
        }
    }
}
