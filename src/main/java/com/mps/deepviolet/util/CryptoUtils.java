package com.mps.deepviolet.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encryption utilities for DeepViolet scan persistence.
 * Provides AES-256-GCM encryption/decryption, DEK generation and wrapping,
 * password-based key derivation, HMAC-SHA256, and machine key management.
 *
 * @author Milton Smith
 */
public class CryptoUtils {

	private static final Logger logger = LoggerFactory
			.getLogger("com.mps.deepviolet.util.CryptoUtils");

	private static final String GLOBAL_DIR_NAME = ".deepviolet";
	private static final String GLOBAL_PROPS_FILE = "global.properties";
	private static final String KEY_ENCRYPTION_SEED = "security.encryptionSeed";
	private static final int GCM_IV_BYTES = 12;
	private static final int GCM_TAG_BITS = 128;
	private static final int DEK_BYTES = 32;
	private static final int SALT_BYTES = 16;
	private static final int DEFAULT_KDF_ITERATIONS = 600_000;

	// ---- Machine key management ----

	/**
	 * Ensure a machine encryption seed exists in global properties.
	 * Creates one if not present. Migrates from local properties if found.
	 */
	public static void ensureEncryptionSeed() {
		Properties globalProps = loadGlobalProperties();
		if (globalProps.getProperty(KEY_ENCRYPTION_SEED) != null) {
			return;
		}

		// Generate a new seed
		byte[] seed = new byte[DEK_BYTES];
		new SecureRandom().nextBytes(seed);
		globalProps.setProperty(KEY_ENCRYPTION_SEED,
				Base64.getEncoder().encodeToString(seed));
		saveGlobalProperties(globalProps);
		logger.info("Encryption seed generated");
	}

	/**
	 * Retrieve the 32-byte machine encryption key.
	 *
	 * @return 32-byte AES key, or null if not generated
	 */
	public static byte[] getEncryptionSeed() {
		String seedB64 = loadGlobalProperties().getProperty(KEY_ENCRYPTION_SEED);
		if (seedB64 == null) {
			return null;
		}
		return Base64.getDecoder().decode(seedB64);
	}

	// ---- AES-256-GCM ----

	/**
	 * Encrypt plaintext with AES-256-GCM.
	 *
	 * @param plaintext data to encrypt
	 * @param key       32-byte AES key
	 * @return IV (12 bytes) || ciphertext || GCM tag (16 bytes)
	 * @throws GeneralSecurityException on encryption failure
	 */
	public static byte[] encryptBytes(byte[] plaintext, byte[] key)
			throws GeneralSecurityException {
		SecureRandom sr = new SecureRandom();
		byte[] iv = new byte[GCM_IV_BYTES];
		sr.nextBytes(iv);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE,
				new SecretKeySpec(key, "AES"),
				new GCMParameterSpec(GCM_TAG_BITS, iv));
		byte[] ciphertext = cipher.doFinal(plaintext);

		byte[] result = new byte[iv.length + ciphertext.length];
		System.arraycopy(iv, 0, result, 0, iv.length);
		System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
		return result;
	}

	/**
	 * Decrypt AES-256-GCM encrypted data.
	 *
	 * @param data IV (12 bytes) || ciphertext || GCM tag (16 bytes)
	 * @param key  32-byte AES key
	 * @return decrypted plaintext
	 * @throws GeneralSecurityException on decryption failure (wrong key, tampered data)
	 */
	public static byte[] decryptBytes(byte[] data, byte[] key)
			throws GeneralSecurityException {
		byte[] iv = new byte[GCM_IV_BYTES];
		System.arraycopy(data, 0, iv, 0, GCM_IV_BYTES);
		byte[] ciphertext = new byte[data.length - GCM_IV_BYTES];
		System.arraycopy(data, GCM_IV_BYTES, ciphertext, 0, ciphertext.length);

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE,
				new SecretKeySpec(key, "AES"),
				new GCMParameterSpec(GCM_TAG_BITS, iv));
		return cipher.doFinal(ciphertext);
	}

	// ---- DEK generation and wrapping ----

	/**
	 * Generate a random 32-byte Data Encryption Key.
	 *
	 * @return 32 random bytes
	 */
	public static byte[] generateDek() {
		byte[] dek = new byte[DEK_BYTES];
		new SecureRandom().nextBytes(dek);
		return dek;
	}

	/**
	 * Wrap (encrypt) a DEK with a KEK using AES-256-GCM.
	 *
	 * @param dek DEK to wrap
	 * @param kek Key Encryption Key
	 * @return wrapped DEK (IV || ciphertext || tag)
	 * @throws GeneralSecurityException on wrapping failure
	 */
	public static byte[] wrapDek(byte[] dek, byte[] kek)
			throws GeneralSecurityException {
		return encryptBytes(dek, kek);
	}

	/**
	 * Unwrap (decrypt) a DEK with a KEK using AES-256-GCM.
	 *
	 * @param wrappedDek wrapped DEK (IV || ciphertext || tag)
	 * @param kek        Key Encryption Key
	 * @return unwrapped DEK
	 * @throws GeneralSecurityException on unwrapping failure (wrong KEK)
	 */
	public static byte[] unwrapDek(byte[] wrappedDek, byte[] kek)
			throws GeneralSecurityException {
		return decryptBytes(wrappedDek, kek);
	}

	// ---- Password-based KDF ----

	/**
	 * Derive a 32-byte KEK from a password using PBKDF2-HMAC-SHA256.
	 *
	 * @param password   user-supplied password
	 * @param salt       random salt (16 bytes recommended)
	 * @param iterations iteration count
	 * @return 32-byte derived KEK
	 * @throws GeneralSecurityException on KDF failure
	 */
	public static byte[] derivePasswordKek(char[] password, byte[] salt,
			int iterations) throws GeneralSecurityException {
		javax.crypto.SecretKeyFactory factory =
				javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		javax.crypto.spec.PBEKeySpec spec =
				new javax.crypto.spec.PBEKeySpec(password, salt, iterations,
						DEK_BYTES * 8);
		try {
			return factory.generateSecret(spec).getEncoded();
		} finally {
			spec.clearPassword();
		}
	}

	/**
	 * Derive a 32-byte KEK using the default iteration count.
	 */
	public static byte[] derivePasswordKek(char[] password, byte[] salt)
			throws GeneralSecurityException {
		return derivePasswordKek(password, salt, DEFAULT_KDF_ITERATIONS);
	}

	/**
	 * Generate a random 16-byte salt.
	 *
	 * @return 16 random bytes
	 */
	public static byte[] generateSalt() {
		byte[] salt = new byte[SALT_BYTES];
		new SecureRandom().nextBytes(salt);
		return salt;
	}

	// ---- HMAC-SHA256 ----

	/**
	 * Compute HMAC-SHA256 over data with the given key.
	 *
	 * @param data data to authenticate
	 * @param key  HMAC key
	 * @return 32-byte HMAC
	 * @throws GeneralSecurityException on HMAC failure
	 */
	public static byte[] hmacSha256(byte[] data, byte[] key)
			throws GeneralSecurityException {
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(new SecretKeySpec(key, "HmacSHA256"));
		return mac.doFinal(data);
	}

	// ---- Hashing ----

	/**
	 * Compute SHA-256 hash of data and return as lowercase hex string.
	 *
	 * @param data bytes to hash
	 * @return 64-character lowercase hex string, or null on failure
	 */
	public static String sha256Hex(byte[] data) {
		try {
			java.security.MessageDigest md =
					java.security.MessageDigest.getInstance("SHA-256");
			byte[] hash = md.digest(data);
			StringBuilder sb = new StringBuilder(64);
			for (byte b : hash) {
				sb.append(String.format("%02x", b));
			}
			return sb.toString();
		} catch (java.security.NoSuchAlgorithmException e) {
			logger.error("SHA-256 not available", e);
			return null;
		}
	}

	// ---- Internal ----

	/**
	 * Get the global configuration directory.
	 * Default: {@code ~/.deepviolet/}. Override with system property
	 * {@code deepviolet.global}.
	 *
	 * @return global directory
	 */
	public static File getGlobalDir() {
		String override = System.getProperty("deepviolet.global");
		if (override != null && !override.isEmpty()) {
			return new File(override);
		}
		return new File(System.getProperty("user.home"), GLOBAL_DIR_NAME);
	}

	private static Properties loadGlobalProperties() {
		Properties props = new Properties();
		File file = new File(getGlobalDir(), GLOBAL_PROPS_FILE);
		if (file.exists()) {
			try (FileInputStream in = new FileInputStream(file)) {
				props.load(in);
			} catch (IOException e) {
				logger.error("Failed to load global properties file", e);
			}
		}
		return props;
	}

	private static void saveGlobalProperties(Properties props) {
		File dir = getGlobalDir();
		dir.mkdirs();
		File file = new File(dir, GLOBAL_PROPS_FILE);
		try (FileOutputStream out = new FileOutputStream(file)) {
			props.store(out, "DeepViolet global settings — do not delete");
		} catch (IOException e) {
			logger.error("Failed to save global properties file", e);
		}
	}
}
