package com.mps.deepviolet.persist;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Map;

import com.mps.deepviolet.util.CryptoUtils;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Public API for saving and loading encrypted {@code .dvscan} scan files
 * and plain JSON scan snapshots.
 * <p>
 * <b>v2 format</b> uses envelope encryption with dual KEK slots
 * (machine key + optional password). v1 files are read transparently
 * for backward compatibility.
 *
 * @author Milton Smith
 */
public class ScanFileIO {

	private ScanFileIO() {}

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolet.persist.ScanFileIO");

	static final byte[] DVSCAN_MAGIC = { 0x44, 0x56, 0x53, 0x43 };
	static final byte DVSCAN_VERSION_1 = 0x01;
	static final byte DVSCAN_VERSION_2 = 0x02;
	static final int MAGIC_SIZE = 4;
	static final int V1_HEADER_SIZE = 5; // magic + version

	// v2 slot types
	static final byte SLOT_MACHINE = 0x01;
	static final byte SLOT_PASSWORD = 0x02;
	// v2 slot sizes
	static final int WRAPPED_DEK_SIZE = 60; // 12 IV + 32 ciphertext + 16 tag
	static final int MACHINE_SLOT_SIZE = 1 + WRAPPED_DEK_SIZE; // type + wrapped
	static final int PASSWORD_SALT_SIZE = 16;
	static final int PASSWORD_ITERATIONS_SIZE = 4;
	static final int PASSWORD_SLOT_SIZE = 1 + PASSWORD_SALT_SIZE
			+ PASSWORD_ITERATIONS_SIZE + WRAPPED_DEK_SIZE;
	static final int HMAC_SIZE = 32;
	static final int DEFAULT_KDF_ITERATIONS = 600_000;

	private static final ScanJsonCodec codec = new ScanJsonCodec();

	/**
	 * Callback for password prompt during load.
	 * GUI shows dialog; CLI reads from env/stdin.
	 */
	@FunctionalInterface
	public interface PasswordCallback {
		/**
		 * Prompt for and return the password.
		 * @return the password characters
		 * @throws IOException on I/O errors
		 */
		char[] getPassword() throws IOException;
	}

	// ---- Save ----

	/**
	 * Save a scan snapshot using the specified encryption mode.
	 *
	 * @param file      output file
	 * @param snapshot  scan data to save
	 * @param mode      encryption mode (PLAIN_TEXT, HOST_LOCKED, PASSWORD_LOCKED)
	 * @param machineKey 32-byte machine key (ignored for PLAIN_TEXT)
	 * @param password  transfer password (required for PASSWORD_LOCKED, ignored otherwise)
	 * @return scanId (SHA-256 hex of the written file)
	 * @throws IOException on write or encryption failure
	 */
	public static String save(File file, ScanSnapshot snapshot,
			ScanFileMode mode, byte[] machineKey, char[] password) throws IOException {
		return switch (mode) {
			case PLAIN_TEXT -> savePlainText(file, snapshot);
			case HOST_LOCKED -> saveEncrypted(file, snapshot, machineKey, null);
			case PASSWORD_LOCKED -> saveEncrypted(file, snapshot, null, password);
		};
	}

	/**
	 * Save as plain text JSON (no encryption).
	 * The file is portable to any machine but scan data is not protected.
	 *
	 * @param file     output file
	 * @param snapshot scan data to save
	 * @return scanId (SHA-256 hex of the written file)
	 * @throws IOException on write failure
	 */
	public static String savePlainText(File file,
			ScanSnapshot snapshot) throws IOException {
		String json = codec.encode(snapshot);
		Files.writeString(file.toPath(), json, StandardCharsets.UTF_8);

		byte[] written = Files.readAllBytes(file.toPath());
		String sha = CryptoUtils.sha256Hex(written);
		snapshot.setScanId(sha);
		return sha;
	}

	/**
	 * Save with machine-key only (host locked, zero-friction on same machine).
	 * @param file target file
	 * @param snapshot scan snapshot to save
	 * @param machineKey machine encryption key
	 * @return SHA-256 hash of the written file
	 * @throws IOException on I/O errors
	 */
	public static String save(File file, ScanSnapshot snapshot,
			byte[] machineKey) throws IOException {
		return saveEncrypted(file, snapshot, machineKey, null);
	}

	/**
	 * Save with password only (password locked, always requires password to open).
	 * If password is null or empty, falls back to host locked (machine key only).
	 * @param file target file
	 * @param snapshot scan snapshot to save
	 * @param machineKey machine encryption key
	 * @param password user password, or null for host locked
	 * @return SHA-256 hash of the written file
	 * @throws IOException on I/O errors
	 */
	public static String save(File file, ScanSnapshot snapshot,
			byte[] machineKey, char[] password) throws IOException {
		if (password != null && password.length > 0) {
			return saveEncrypted(file, snapshot, null, password);
		}
		return saveEncrypted(file, snapshot, machineKey, null);
	}

	/**
	 * Internal: save with either machine key, password, or both.
	 * At least one of machineKey or password must be non-null.
	 */
	private static String saveEncrypted(File file, ScanSnapshot snapshot,
			byte[] machineKey, char[] password) throws IOException {
		String json = codec.encode(snapshot);
		byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);

		try {
			byte[] dek = CryptoUtils.generateDek();
			byte[] encryptedPayload = CryptoUtils.encryptBytes(jsonBytes, dek);

			// Build slot array — include only the slots that apply
			ByteArrayOutputStream slotsOut = new ByteArrayOutputStream();
			int slotCount = 0;

			// Machine key slot (host locked)
			if (machineKey != null) {
				slotCount++;
				byte[] wrappedMachine = CryptoUtils.wrapDek(dek, machineKey);
				slotsOut.write(SLOT_MACHINE);
				slotsOut.write(wrappedMachine);
			}

			// Password slot (password locked)
			if (password != null && password.length > 0) {
				slotCount++;
				byte[] salt = CryptoUtils.generateSalt();
				byte[] passwordKek = CryptoUtils.derivePasswordKek(
						password, salt, DEFAULT_KDF_ITERATIONS);
				byte[] wrappedPassword = CryptoUtils.wrapDek(dek, passwordKek);
				slotsOut.write(SLOT_PASSWORD);
				slotsOut.write(salt);
				writeInt(slotsOut, DEFAULT_KDF_ITERATIONS);
				slotsOut.write(wrappedPassword);
			}

			if (slotCount == 0) {
				throw new IOException("At least one of machineKey or password must be provided");
			}

			byte[] slotBytes = slotsOut.toByteArray();

			// Compute slot integrity HMAC
			byte[] hmac = CryptoUtils.hmacSha256(slotBytes, dek);

			// Build output: magic + version + slotCount + hmac + slots + payload
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			out.write(DVSCAN_MAGIC);
			out.write(DVSCAN_VERSION_2);
			out.write(slotCount);
			out.write(hmac);
			out.write(slotBytes);
			out.write(encryptedPayload);

			Files.write(file.toPath(), out.toByteArray());

			byte[] written = Files.readAllBytes(file.toPath());
			String sha = CryptoUtils.sha256Hex(written);
			snapshot.setScanId(sha);
			return sha;

		} catch (GeneralSecurityException e) {
			throw new IOException("Encryption failed: " + e.getMessage(), e);
		}
	}

	// ---- Load ----

	/**
	 * Load with machine key only. Throws if password is required.
	 * @param file source file
	 * @param machineKey machine encryption key
	 * @return loaded scan snapshot
	 * @throws IOException on I/O or decryption errors
	 */
	public static ScanSnapshot load(File file, byte[] machineKey)
			throws IOException {
		return load(file, machineKey, null);
	}

	/**
	 * Load a scan file with machine key + optional password callback.
	 * Auto-detects the file format: encrypted binary (v1/v2) or plain JSON.
	 * @param file source file
	 * @param machineKey machine encryption key
	 * @param passwordCallback callback for password prompts, or null
	 * @return loaded scan snapshot
	 * @throws IOException on I/O or decryption errors
	 */
	public static ScanSnapshot load(File file, byte[] machineKey,
			PasswordCallback passwordCallback) throws IOException {
		byte[] data = Files.readAllBytes(file.toPath());

		if (data.length < V1_HEADER_SIZE) {
			throw new IOException("File too small to be a valid .dvscan file");
		}

		// Check for DVSC magic header
		boolean hasMagic = true;
		for (int i = 0; i < DVSCAN_MAGIC.length; i++) {
			if (data[i] != DVSCAN_MAGIC[i]) {
				hasMagic = false;
				break;
			}
		}

		ScanSnapshot result;
		if (hasMagic) {
			byte version = data[MAGIC_SIZE];
			if (version == DVSCAN_VERSION_1) {
				result = loadV1(data, machineKey);
			} else if (version == DVSCAN_VERSION_2) {
				result = loadV2(data, machineKey, passwordCallback);
			} else {
				throw new IOException("Unsupported .dvscan format version: "
						+ (version & 0xFF));
			}
		} else {
			// No DVSC magic — try plain JSON
			try {
				result = decodeJson(data);
			} catch (Exception e) {
				throw new IOException("File is neither encrypted .dvscan "
						+ "nor valid JSON: " + e.getMessage(), e);
			}
		}

		String sha = CryptoUtils.sha256Hex(data);
		result.setScanId(sha);

		return result;
	}

	private static ScanSnapshot loadV1(byte[] data, byte[] machineKey)
			throws IOException {
		if (machineKey == null) {
			throw new IOException("Encryption seed not available. "
					+ "Cannot decrypt v1 scan file.");
		}

		byte[] encrypted = new byte[data.length - V1_HEADER_SIZE];
		System.arraycopy(data, V1_HEADER_SIZE, encrypted, 0, encrypted.length);

		byte[] jsonBytes;
		try {
			jsonBytes = CryptoUtils.decryptBytes(encrypted, machineKey);
		} catch (Exception e) {
			throw new IOException("Failed to decrypt v1 scan file — "
					+ "the file may be tampered or corrupted", e);
		}

		return decodeJson(jsonBytes);
	}

	private static ScanSnapshot loadV2(byte[] data, byte[] machineKey,
			PasswordCallback passwordCallback) throws IOException {
		int offset = MAGIC_SIZE + 1; // past magic + version
		int slotCount = data[offset] & 0xFF;
		offset++;

		// Read HMAC (32 bytes)
		byte[] storedHmac = new byte[HMAC_SIZE];
		System.arraycopy(data, offset, storedHmac, 0, HMAC_SIZE);
		offset += HMAC_SIZE;

		// Read slot array
		int slotsStart = offset;
		byte[] dek = null;

		// Parse slots and try to unwrap DEK
		byte[] passwordSlotSalt = null;
		int passwordSlotIterations = 0;
		byte[] passwordSlotWrapped = null;

		for (int i = 0; i < slotCount; i++) {
			byte slotType = data[offset];
			offset++;

			if (slotType == SLOT_MACHINE) {
				byte[] wrappedDek = new byte[WRAPPED_DEK_SIZE];
				System.arraycopy(data, offset, wrappedDek, 0, WRAPPED_DEK_SIZE);
				offset += WRAPPED_DEK_SIZE;

				// Try machine key
				if (machineKey != null && dek == null) {
					try {
						dek = CryptoUtils.unwrapDek(wrappedDek, machineKey);
					} catch (GeneralSecurityException e) {
						logger.debug("Machine key failed to unwrap DEK");
					}
				}
			} else if (slotType == SLOT_PASSWORD) {
				passwordSlotSalt = new byte[PASSWORD_SALT_SIZE];
				System.arraycopy(data, offset, passwordSlotSalt, 0,
						PASSWORD_SALT_SIZE);
				offset += PASSWORD_SALT_SIZE;

				passwordSlotIterations = readInt(data, offset);
				offset += PASSWORD_ITERATIONS_SIZE;

				passwordSlotWrapped = new byte[WRAPPED_DEK_SIZE];
				System.arraycopy(data, offset, passwordSlotWrapped, 0,
						WRAPPED_DEK_SIZE);
				offset += WRAPPED_DEK_SIZE;
			} else {
				throw new IOException("Unknown slot type: " + (slotType & 0xFF));
			}
		}

		int slotsEnd = offset;
		byte[] slotBytes = new byte[slotsEnd - slotsStart];
		System.arraycopy(data, slotsStart, slotBytes, 0, slotBytes.length);

		// If machine key failed, try password slot
		if (dek == null && passwordSlotWrapped != null) {
			if (passwordCallback == null) {
				throw new IOException("Machine key cannot decrypt this file "
						+ "and no password callback provided. "
						+ "A transfer password is required.");
			}
			char[] password = passwordCallback.getPassword();
			if (password == null) {
				throw new IOException("Password is required to decrypt this file");
			}
			try {
				byte[] passwordKek = CryptoUtils.derivePasswordKek(
						password, passwordSlotSalt, passwordSlotIterations);
				dek = CryptoUtils.unwrapDek(passwordSlotWrapped, passwordKek);
			} catch (GeneralSecurityException e) {
				throw new IOException("Password failed to decrypt the file", e);
			}
		}

		if (dek == null) {
			throw new IOException("Cannot decrypt .dvscan file — "
					+ "neither machine key nor password worked");
		}

		// Verify slot integrity HMAC
		try {
			byte[] computedHmac = CryptoUtils.hmacSha256(slotBytes, dek);
			if (!java.security.MessageDigest.isEqual(storedHmac, computedHmac)) {
				throw new IOException("Slot integrity check failed — "
						+ "the .dvscan file may have been tampered with");
			}
		} catch (GeneralSecurityException e) {
			throw new IOException("Failed to verify slot integrity", e);
		}

		// Decrypt payload
		byte[] encryptedPayload = new byte[data.length - offset];
		System.arraycopy(data, offset, encryptedPayload, 0,
				encryptedPayload.length);

		byte[] jsonBytes;
		try {
			jsonBytes = CryptoUtils.decryptBytes(encryptedPayload, dek);
		} catch (Exception e) {
			throw new IOException("Failed to decrypt scan payload", e);
		}

		return decodeJson(jsonBytes);
	}

	// ---- Plain JSON ----

	/**
	 * Serialize a snapshot to plain JSON (no encryption).
	 * @param snapshot scan snapshot to serialize
	 * @return JSON string
	 */
	public static String toJson(ScanSnapshot snapshot) {
		return codec.encode(snapshot);
	}

	/**
	 * Deserialize a snapshot from a plain JSON string.
	 * @param json JSON string
	 * @return deserialized scan snapshot
	 */
	public static ScanSnapshot fromJson(String json) {
		Gson gson = new Gson();
		Map<String, Object> jsonMap = gson.fromJson(json,
				new TypeToken<Map<String, Object>>() {}.getType());
		return codec.decode(jsonMap);
	}

	/**
	 * Deserialize a snapshot from a plain JSON input stream.
	 * @param in input stream containing JSON
	 * @return deserialized scan snapshot
	 * @throws IOException on I/O errors
	 */
	public static ScanSnapshot fromJson(InputStream in) throws IOException {
		String json = new String(in.readAllBytes(), StandardCharsets.UTF_8);
		return fromJson(json);
	}

	// ---- Internal ----

	private static ScanSnapshot decodeJson(byte[] jsonBytes) {
		String json = new String(jsonBytes, StandardCharsets.UTF_8);
		Gson gson = new Gson();
		Map<String, Object> jsonMap = gson.fromJson(json,
				new TypeToken<Map<String, Object>>() {}.getType());
		return codec.decode(jsonMap);
	}

	private static void writeInt(ByteArrayOutputStream out, int value) {
		out.write((value >> 24) & 0xFF);
		out.write((value >> 16) & 0xFF);
		out.write((value >> 8) & 0xFF);
		out.write(value & 0xFF);
	}

	private static int readInt(byte[] data, int offset) {
		return ((data[offset] & 0xFF) << 24)
				| ((data[offset + 1] & 0xFF) << 16)
				| ((data[offset + 2] & 0xFF) << 8)
				| (data[offset + 3] & 0xFF);
	}
}
