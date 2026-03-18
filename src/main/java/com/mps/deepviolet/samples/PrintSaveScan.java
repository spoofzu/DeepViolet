package com.mps.deepviolet.samples;

import java.io.File;
import java.net.URL;
import java.util.EnumSet;
import java.util.List;

import com.mps.deepviolet.api.*;
import com.mps.deepviolet.persist.*;
import com.mps.deepviolet.util.CryptoUtils;

/**
 * Demonstrates scanning one or more hosts and saving the results
 * to a {@code .dvscan} file that can be opened later for analysis
 * or transferred to another machine.
 *
 * <p>Workflow: scan targets, collect results into a
 * {@link ScanSnapshot}, save to disk, then reload and verify.</p>
 */
public class PrintSaveScan {

	/** Runs the scan-and-save demo.
	 *  @throws Exception on scan or I/O errors */
	public PrintSaveScan() throws Exception {

		// Scan two hosts
		List<String> targets = List.of("github.com", "google.com");

		ScanConfig config = ScanConfig.builder()
				.threadCount(2)
				.enabledSections(EnumSet.of(
						ScanSection.SESSION_INIT,
						ScanSection.CIPHER_ENUMERATION,
						ScanSection.RISK_SCORING))
				.build();

		System.out.println("Scanning " + targets + " ...");
		List<IScanResult> results = TlsScanner.scan(targets, config, null);

		// Build a snapshot from scan results
		ScanSnapshot snapshot = new ScanSnapshot();
		snapshot.setTotalTargets(results.size());

		int successes = 0;
		for (IScanResult result : results) {
			HostSnapshot host = new HostSnapshot(result.getURL().toString());
			if (result.isSuccess()) {
				successes++;
				IEngine eng = result.getEngine();
				host.setRiskScore(eng.getRiskScore());
				host.setCiphers(eng.getCipherSuites());
			} else {
				host.setErrorMessage(result.getError().getMessage());
			}
			snapshot.addHost(host);
		}
		snapshot.setSuccessCount(successes);
		snapshot.setErrorCount(results.size() - successes);

		// Save as plain text (portable, no encryption)
		File outFile = new File("multi-host-scan.dvscan");
		String scanId = ScanFileIO.save(outFile, snapshot,
				ScanFileMode.PLAIN_TEXT, null, null);
		System.out.println("Saved: " + outFile.getName()
				+ " (scanId=" + scanId.substring(0, 12) + "...)");

		// Reload and verify
		ScanSnapshot loaded = ScanFileIO.load(outFile, null);
		System.out.println("Loaded: " + loaded.getHosts().size() + " host(s), "
				+ loaded.getSuccessCount() + " succeeded");
		for (HostSnapshot h : loaded.getHosts()) {
			if (h.isSuccess()) {
				System.out.printf("  %s — grade %s, %d ciphers%n",
						h.getTargetUrl(),
						h.getRiskScore().getLetterGrade().toDisplayString(),
						h.getCiphers() != null ? h.getCiphers().length : 0);
			} else {
				System.out.printf("  %s — ERROR: %s%n",
						h.getTargetUrl(), h.getErrorMessage());
			}
		}
	}

	/** Entry point.
	 *  @param args not used */
	public static final void main(String[] args) {
		try {
			new PrintSaveScan();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
