package com.mps.deepviolet.samples;

import java.io.File;
import java.net.URL;

import com.mps.deepviolet.api.*;
import com.mps.deepviolet.persist.*;
import com.mps.deepviolet.util.CryptoUtils;

/**
 * Demonstrates the three scan persistence modes:
 * <ol>
 *   <li><b>Plain text</b> — unencrypted JSON, portable everywhere</li>
 *   <li><b>Host locked</b> — encrypted with machine key, zero-friction on same host</li>
 *   <li><b>Password locked</b> — encrypted with machine key + password, portable across hosts</li>
 * </ol>
 *
 * <p>A common workflow: run a TLS scan on a remote server and save as password
 * locked, then transfer the {@code .dvscan} file to a workstation and open it
 * in the DeepVioletTools GUI for visual analysis.</p>
 */
public class PrintScanPersistence {

	public PrintScanPersistence() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);

		// Build a snapshot from engine state
		HostSnapshot host = new HostSnapshot("https://github.com/");
		host.setRiskScore(eng.getRiskScore());
		host.setCiphers(eng.getCipherSuites());

		ScanSnapshot snapshot = new ScanSnapshot();
		snapshot.setTotalTargets(1);
		snapshot.setSuccessCount(1);
		snapshot.addHost(host);

		// Ensure machine encryption key exists
		CryptoUtils.ensureEncryptionSeed();
		byte[] machineKey = CryptoUtils.getEncryptionSeed();

		// --- Mode 1: Plain text (no encryption) ---
		File plainFile = new File("scan-plain.dvscan");
		ScanFileIO.save(plainFile, snapshot, ScanFileMode.PLAIN_TEXT, null, null);
		System.out.println("Plain text saved: " + plainFile.getName());

		// --- Mode 2: Host locked (machine key only) ---
		File hostFile = new File("scan-host-locked.dvscan");
		ScanFileIO.save(hostFile, snapshot, ScanFileMode.HOST_LOCKED, machineKey, null);
		System.out.println("Host locked saved: " + hostFile.getName());

		// --- Mode 3: Password locked (machine key + transfer password) ---
		File pwFile = new File("scan-password-locked.dvscan");
		char[] password = "transfer-password".toCharArray();
		ScanFileIO.save(pwFile, snapshot, ScanFileMode.PASSWORD_LOCKED, machineKey, password);
		System.out.println("Password locked saved: " + pwFile.getName());

		// Load auto-detects format: plain JSON, v1 encrypted, v2 encrypted
		ScanSnapshot fromPlain = ScanFileIO.load(plainFile, null);
		System.out.println("Loaded plain text: " + fromPlain.getHosts().size() + " host(s)");

		ScanSnapshot fromHost = ScanFileIO.load(hostFile, machineKey);
		System.out.println("Loaded host locked: " + fromHost.getHosts().size() + " host(s)");

		// Load password-locked on same machine — machine key works silently
		ScanSnapshot fromPwLocal = ScanFileIO.load(pwFile, machineKey);
		System.out.println("Loaded password locked (same host): "
				+ fromPwLocal.getHosts().size() + " host(s)");

		// Load password-locked on different machine — password callback fires
		byte[] otherMachineKey = new byte[32]; // wrong key simulates another host
		ScanSnapshot fromPwRemote = ScanFileIO.load(pwFile, otherMachineKey,
				() -> "transfer-password".toCharArray());
		System.out.println("Loaded password locked (remote host): "
				+ fromPwRemote.getHosts().size() + " host(s)");
	}

	public static final void main(String[] args) {
		try {
			new PrintScanPersistence();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
