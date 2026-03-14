package com.mps.deepviolet.util;

import static org.junit.jupiter.api.Assertions.*;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link CryptoUtils}.
 */
class CryptoUtilsTest {

	@Test
	void testEncryptDecryptRoundTrip() throws GeneralSecurityException {
		byte[] key = CryptoUtils.generateDek();
		byte[] plaintext = "Hello, DeepViolet!".getBytes();

		byte[] encrypted = CryptoUtils.encryptBytes(plaintext, key);
		assertNotNull(encrypted);
		assertTrue(encrypted.length > plaintext.length);

		byte[] decrypted = CryptoUtils.decryptBytes(encrypted, key);
		assertArrayEquals(plaintext, decrypted);
	}

	@Test
	void testDecryptWithWrongKey_throws() {
		byte[] key1 = CryptoUtils.generateDek();
		byte[] key2 = CryptoUtils.generateDek();
		byte[] plaintext = "secret data".getBytes();

		assertThrows(GeneralSecurityException.class, () -> {
			byte[] encrypted = CryptoUtils.encryptBytes(plaintext, key1);
			CryptoUtils.decryptBytes(encrypted, key2);
		});
	}

	@Test
	void testDekGeneration() {
		byte[] dek = CryptoUtils.generateDek();
		assertNotNull(dek);
		assertEquals(32, dek.length);

		// Two DEKs should be different
		byte[] dek2 = CryptoUtils.generateDek();
		assertFalse(java.util.Arrays.equals(dek, dek2));
	}

	@Test
	void testDekWrapUnwrap() throws GeneralSecurityException {
		byte[] dek = CryptoUtils.generateDek();
		byte[] kek = CryptoUtils.generateDek();

		byte[] wrapped = CryptoUtils.wrapDek(dek, kek);
		assertNotNull(wrapped);
		assertTrue(wrapped.length > dek.length);

		byte[] unwrapped = CryptoUtils.unwrapDek(wrapped, kek);
		assertArrayEquals(dek, unwrapped);
	}

	@Test
	void testDekUnwrapWithWrongKek_throws() {
		byte[] dek = CryptoUtils.generateDek();
		byte[] kek1 = CryptoUtils.generateDek();
		byte[] kek2 = CryptoUtils.generateDek();

		assertThrows(GeneralSecurityException.class, () -> {
			byte[] wrapped = CryptoUtils.wrapDek(dek, kek1);
			CryptoUtils.unwrapDek(wrapped, kek2);
		});
	}

	@Test
	void testPasswordKdf() throws GeneralSecurityException {
		char[] password = "test-password".toCharArray();
		byte[] salt = CryptoUtils.generateSalt();
		assertEquals(16, salt.length);

		byte[] kek = CryptoUtils.derivePasswordKek(password, salt, 1000);
		assertNotNull(kek);
		assertEquals(32, kek.length);

		// Same password + salt = same key
		byte[] kek2 = CryptoUtils.derivePasswordKek(password, salt, 1000);
		assertArrayEquals(kek, kek2);

		// Different salt = different key
		byte[] salt2 = CryptoUtils.generateSalt();
		byte[] kek3 = CryptoUtils.derivePasswordKek(password, salt2, 1000);
		assertFalse(java.util.Arrays.equals(kek, kek3));
	}

	@Test
	void testHmacSha256() throws GeneralSecurityException {
		byte[] data = "test data".getBytes();
		byte[] key = CryptoUtils.generateDek();

		byte[] hmac = CryptoUtils.hmacSha256(data, key);
		assertNotNull(hmac);
		assertEquals(32, hmac.length);

		// Same data + key = same HMAC
		byte[] hmac2 = CryptoUtils.hmacSha256(data, key);
		assertArrayEquals(hmac, hmac2);

		// Different data = different HMAC
		byte[] hmac3 = CryptoUtils.hmacSha256("other data".getBytes(), key);
		assertFalse(java.util.Arrays.equals(hmac, hmac3));
	}

	@Test
	void testSha256Hex() {
		String hash = CryptoUtils.sha256Hex("test".getBytes());
		assertNotNull(hash);
		assertEquals(64, hash.length());
		// Known SHA-256 of "test"
		assertEquals("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
				hash);
	}

	@Test
	void testSaltGeneration() {
		byte[] salt = CryptoUtils.generateSalt();
		assertNotNull(salt);
		assertEquals(16, salt.length);

		byte[] salt2 = CryptoUtils.generateSalt();
		assertFalse(java.util.Arrays.equals(salt, salt2));
	}
}
