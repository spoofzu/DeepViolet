package com.mps.deepviolet.persist;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Map;

import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.util.CryptoUtils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unit tests for {@link ScanFileIO}.
 */
class ScanFileIOTest {

	@TempDir
	File tempDir;

	private ScanSnapshot createTestSnapshot() {
		ScanSnapshot snapshot = new ScanSnapshot();
		snapshot.setTotalTargets(1);
		snapshot.setSuccessCount(1);
		snapshot.setErrorCount(0);

		HostSnapshot host = new HostSnapshot("https://example.com/");
		host.setTlsFingerprint("abc123");
		host.setSecurityHeaders(Map.of("Strict-Transport-Security", "max-age=31536000"));
		host.setCiphers(new ImmutableCipherSuite[]{
				new ImmutableCipherSuite("TLS_AES_256_GCM_SHA384", "STRONG", "TLSv1.3")
		});
		host.setRiskScore(new ImmutableRiskScore(85,
				IRiskScore.LetterGrade.B,
				IRiskScore.RiskLevel.MEDIUM,
				new IRiskScore.ICategoryScore[]{
						new ImmutableCategoryScore("PROTOCOLS", "Protocols", 18,
								IRiskScore.RiskLevel.LOW, "Good protocol support",
								new IRiskScore.IDeduction[]{
										new ImmutableDeduction("SYS-0010100",
												"TLS 1.0 supported", 2.0,
												"MEDIUM", false)
								})
				}));
		snapshot.addHost(host);
		return snapshot;
	}

	@Test
	void testV2MachineKeyOnlyRoundTrip() throws IOException {
		byte[] machineKey = CryptoUtils.generateDek();
		ScanSnapshot original = createTestSnapshot();

		File file = new File(tempDir, "test.dvscan");
		String scanId = ScanFileIO.save(file, original, machineKey);
		assertNotNull(scanId);
		assertEquals(64, scanId.length());

		ScanSnapshot loaded = ScanFileIO.load(file, machineKey);
		assertNotNull(loaded);
		assertEquals(1, loaded.getTotalTargets());
		assertEquals(1, loaded.getHosts().size());
		assertEquals("https://example.com/", loaded.getHosts().get(0).getTargetUrl());
		assertEquals("abc123", loaded.getHosts().get(0).getTlsFingerprint());
		assertNotNull(loaded.getHosts().get(0).getRiskScore());
		assertEquals(85, loaded.getHosts().get(0).getRiskScore().getTotalScore());
		assertNotNull(loaded.getScanId());
		assertEquals(64, loaded.getScanId().length());
	}

	@Test
	void testPasswordLockedRequiresPassword() throws IOException {
		byte[] machineKey = CryptoUtils.generateDek();
		char[] password = "transfer-pw".toCharArray();
		ScanSnapshot original = createTestSnapshot();

		File file = new File(tempDir, "test-pw.dvscan");
		ScanFileIO.save(file, original, machineKey, password);

		// Machine key alone should NOT work — password-locked has no machine slot
		assertThrows(IOException.class, () -> ScanFileIO.load(file, machineKey));

		// Password is required
		ScanSnapshot loaded = ScanFileIO.load(file, null,
				() -> "transfer-pw".toCharArray());
		assertNotNull(loaded);
		assertEquals(1, loaded.getHosts().size());
	}

	@Test
	void testPasswordLockedPortableAcrossMachines() throws IOException {
		byte[] machineKey = CryptoUtils.generateDek();
		char[] password = "transfer-pw".toCharArray();
		ScanSnapshot original = createTestSnapshot();

		File file = new File(tempDir, "cross-machine.dvscan");
		ScanFileIO.save(file, original, machineKey, password);

		// Load on a different machine (different key) with correct password
		byte[] otherMachineKey = CryptoUtils.generateDek();
		ScanSnapshot loaded = ScanFileIO.load(file, otherMachineKey,
				() -> "transfer-pw".toCharArray());
		assertNotNull(loaded);
		assertEquals(1, loaded.getHosts().size());
		assertEquals("https://example.com/",
				loaded.getHosts().get(0).getTargetUrl());
	}

	@Test
	void testPasswordLocked_wrongPassword_throws() throws IOException {
		byte[] machineKey = CryptoUtils.generateDek();
		char[] password = "correct-pw".toCharArray();
		ScanSnapshot original = createTestSnapshot();

		File file = new File(tempDir, "wrong-pw.dvscan");
		ScanFileIO.save(file, original, machineKey, password);

		byte[] otherMachineKey = CryptoUtils.generateDek();
		assertThrows(IOException.class, () ->
				ScanFileIO.load(file, otherMachineKey,
						() -> "wrong-pw".toCharArray()));
	}

	@Test
	void testSlotTamperDetection() throws Exception {
		byte[] machineKey = CryptoUtils.generateDek();
		ScanSnapshot original = createTestSnapshot();

		File file = new File(tempDir, "tamper.dvscan");
		ScanFileIO.save(file, original, machineKey);

		// Tamper with a byte in the slot area (after HMAC)
		byte[] data = Files.readAllBytes(file.toPath());
		int slotAreaStart = ScanFileIO.MAGIC_SIZE + 1 + 1 + ScanFileIO.HMAC_SIZE;
		data[slotAreaStart + 5] ^= 0xFF; // flip a byte in the slot
		Files.write(file.toPath(), data);

		// Loading should fail — either DEK unwrap fails or HMAC check fails
		assertThrows(IOException.class, () ->
				ScanFileIO.load(file, machineKey));
	}

	@Test
	void testBadMagic_fallsBackToJson_thenFails() throws IOException {
		File file = new File(tempDir, "bad-magic.dvscan");
		Files.write(file.toPath(), new byte[]{ 0x00, 0x00, 0x00, 0x00, 0x01 });

		byte[] machineKey = CryptoUtils.generateDek();
		IOException ex = assertThrows(IOException.class, () ->
				ScanFileIO.load(file, machineKey));
		assertTrue(ex.getMessage().contains("neither encrypted") || ex.getMessage().contains("not valid JSON"),
				"Should fail with format error: " + ex.getMessage());
	}

	@Test
	void testFileTooSmall_throws() throws IOException {
		File file = new File(tempDir, "small.dvscan");
		Files.write(file.toPath(), new byte[]{ 0x44, 0x56 });

		byte[] machineKey = CryptoUtils.generateDek();
		assertThrows(IOException.class, () ->
				ScanFileIO.load(file, machineKey));
	}

	@Test
	void testSavePlainTextFileRoundTrip() throws IOException {
		ScanSnapshot original = createTestSnapshot();

		File file = new File(tempDir, "plain.dvscan");
		String scanId = ScanFileIO.savePlainText(file, original);
		assertNotNull(scanId);
		assertEquals(64, scanId.length());

		// Load auto-detects plain JSON (no DVSC magic)
		ScanSnapshot loaded = ScanFileIO.load(file, null);
		assertNotNull(loaded);
		assertEquals(1, loaded.getHosts().size());
		assertEquals("https://example.com/",
				loaded.getHosts().get(0).getTargetUrl());
		assertEquals(85,
				loaded.getHosts().get(0).getRiskScore().getTotalScore());
	}

	@Test
	void testSaveWithModeEnum() throws IOException {
		byte[] machineKey = CryptoUtils.generateDek();
		ScanSnapshot original = createTestSnapshot();

		// PLAIN_TEXT mode
		File plainFile = new File(tempDir, "mode-plain.dvscan");
		ScanFileIO.save(plainFile, original, ScanFileMode.PLAIN_TEXT, null, null);
		ScanSnapshot fromPlain = ScanFileIO.load(plainFile, null);
		assertEquals(1, fromPlain.getHosts().size());

		// HOST_LOCKED mode
		File hostFile = new File(tempDir, "mode-host.dvscan");
		ScanFileIO.save(hostFile, original, ScanFileMode.HOST_LOCKED, machineKey, null);
		ScanSnapshot fromHost = ScanFileIO.load(hostFile, machineKey);
		assertEquals(1, fromHost.getHosts().size());

		// PASSWORD_LOCKED mode — requires password, machine key alone won't work
		File pwFile = new File(tempDir, "mode-pw.dvscan");
		ScanFileIO.save(pwFile, original, ScanFileMode.PASSWORD_LOCKED,
				machineKey, "test-pw".toCharArray());
		assertThrows(IOException.class, () -> ScanFileIO.load(pwFile, machineKey));
		ScanSnapshot fromPw = ScanFileIO.load(pwFile, null,
				() -> "test-pw".toCharArray());
		assertEquals(1, fromPw.getHosts().size());
	}

	@Test
	void testPlainJsonRoundTrip() {
		ScanSnapshot original = createTestSnapshot();

		String json = ScanFileIO.toJson(original);
		assertNotNull(json);
		assertTrue(json.contains("example.com"));

		ScanSnapshot loaded = ScanFileIO.fromJson(json);
		assertNotNull(loaded);
		assertEquals(1, loaded.getHosts().size());
		assertEquals("https://example.com/",
				loaded.getHosts().get(0).getTargetUrl());
		assertEquals(85,
				loaded.getHosts().get(0).getRiskScore().getTotalScore());
	}

	@Test
	void testV1BackwardCompat() throws Exception {
		// Simulate a v1 file: magic + version 0x01 + AES-256-GCM encrypted JSON
		byte[] machineKey = CryptoUtils.generateDek();
		ScanSnapshot original = createTestSnapshot();

		ScanJsonCodec codec = new ScanJsonCodec();
		byte[] jsonBytes = codec.encode(original).getBytes(java.nio.charset.StandardCharsets.UTF_8);
		byte[] encrypted = CryptoUtils.encryptBytes(jsonBytes, machineKey);

		byte[] v1File = new byte[ScanFileIO.V1_HEADER_SIZE + encrypted.length];
		System.arraycopy(ScanFileIO.DVSCAN_MAGIC, 0, v1File, 0, ScanFileIO.MAGIC_SIZE);
		v1File[ScanFileIO.MAGIC_SIZE] = ScanFileIO.DVSCAN_VERSION_1;
		System.arraycopy(encrypted, 0, v1File, ScanFileIO.V1_HEADER_SIZE, encrypted.length);

		File file = new File(tempDir, "v1.dvscan");
		Files.write(file.toPath(), v1File);

		ScanSnapshot loaded = ScanFileIO.load(file, machineKey);
		assertNotNull(loaded);
		assertEquals(1, loaded.getHosts().size());
		assertEquals("https://example.com/",
				loaded.getHosts().get(0).getTargetUrl());
	}
}
