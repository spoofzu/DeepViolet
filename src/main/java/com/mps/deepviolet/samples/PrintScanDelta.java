package com.mps.deepviolet.samples;

import java.io.File;
import java.util.LinkedHashSet;
import java.util.Set;

import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IRiskScore;
import com.mps.deepviolet.api.IRiskScore.ICategoryScore;
import com.mps.deepviolet.persist.HostSnapshot;
import com.mps.deepviolet.persist.ScanFileIO;
import com.mps.deepviolet.persist.ScanSnapshot;
import com.mps.deepviolet.util.CryptoUtils;

/**
 * Demonstrates comparing two saved {@code .dvscan} files to show
 * what changed between scans (scan delta).
 *
 * <p>Useful for tracking TLS configuration drift over time, verifying
 * that remediation actions took effect, or monitoring changes after
 * server updates.</p>
 *
 * <p>Usage: provide two {@code .dvscan} file paths as arguments, or
 * run with no arguments to use the defaults {@code baseline.dvscan}
 * and {@code current.dvscan}.</p>
 */
public class PrintScanDelta {

	/** Compares two saved scan files and prints differences.
	 *  @param baselineFile the baseline .dvscan file
	 *  @param currentFile the current .dvscan file
	 *  @throws Exception on I/O or decryption errors */
	public PrintScanDelta(File baselineFile, File currentFile) throws Exception {

		CryptoUtils.ensureEncryptionSeed();
		byte[] machineKey = CryptoUtils.getEncryptionSeed();

		ScanSnapshot baseline = ScanFileIO.load(baselineFile, machineKey);
		ScanSnapshot current = ScanFileIO.load(currentFile, machineKey);

		System.out.println("=== Scan Delta ===");
		System.out.println("Baseline: " + baselineFile.getName()
				+ " (" + baseline.getHosts().size() + " host(s))");
		System.out.println("Current:  " + currentFile.getName()
				+ " (" + current.getHosts().size() + " host(s))");
		System.out.println();

		// Match hosts by URL and compare
		for (HostSnapshot curHost : current.getHosts()) {
			HostSnapshot baseHost = findHost(baseline, curHost.getTargetUrl());

			if (baseHost == null) {
				System.out.println("[NEW] " + curHost.getTargetUrl());
				continue;
			}

			System.out.println("--- " + curHost.getTargetUrl() + " ---");

			if (!curHost.isSuccess() || !baseHost.isSuccess()) {
				System.out.println("  Baseline: "
						+ (baseHost.isSuccess() ? "OK" : "ERROR: " + baseHost.getErrorMessage()));
				System.out.println("  Current:  "
						+ (curHost.isSuccess() ? "OK" : "ERROR: " + curHost.getErrorMessage()));
				System.out.println();
				continue;
			}

			// Grade change
			compareGrade(baseHost.getRiskScore(), curHost.getRiskScore());

			// Category score changes
			compareCategoryScores(baseHost.getRiskScore(), curHost.getRiskScore());

			// Cipher suite changes
			compareCiphers(baseHost.getCiphers(), curHost.getCiphers());

			System.out.println();
		}

		// Hosts removed since baseline
		for (HostSnapshot baseHost : baseline.getHosts()) {
			if (findHost(current, baseHost.getTargetUrl()) == null) {
				System.out.println("[REMOVED] " + baseHost.getTargetUrl());
			}
		}
	}

	private void compareGrade(IRiskScore base, IRiskScore cur) {
		if (base == null || cur == null) return;

		String baseGrade = base.getLetterGrade().toDisplayString();
		String curGrade = cur.getLetterGrade().toDisplayString();
		int scoreDiff = cur.getTotalScore() - base.getTotalScore();

		if (scoreDiff == 0) {
			System.out.println("  Grade: " + curGrade + " (unchanged, score " + cur.getTotalScore() + ")");
		} else {
			String arrow = scoreDiff > 0 ? "+" : "";
			System.out.printf("  Grade: %s -> %s (score %d -> %d, %s%d)%n",
					baseGrade, curGrade,
					base.getTotalScore(), cur.getTotalScore(),
					arrow, scoreDiff);
		}
	}

	private void compareCategoryScores(IRiskScore base, IRiskScore cur) {
		if (base == null || cur == null) return;

		for (ICategoryScore curCat : cur.getCategoryScores()) {
			ICategoryScore baseCat = base.getCategoryScore(curCat.getCategoryKey());
			if (baseCat == null) {
				System.out.printf("  [NEW CATEGORY] %s: score %d%n",
						curCat.getDisplayName(), curCat.getScore());
				continue;
			}
			int diff = curCat.getScore() - baseCat.getScore();
			if (diff != 0) {
				String arrow = diff > 0 ? "+" : "";
				System.out.printf("  %s: %d -> %d (%s%d)%n",
						curCat.getDisplayName(),
						baseCat.getScore(), curCat.getScore(),
						arrow, diff);
			}
		}
	}

	private void compareCiphers(ICipherSuite[] baseCiphers, ICipherSuite[] curCiphers) {
		Set<String> baseNames = cipherNames(baseCiphers);
		Set<String> curNames = cipherNames(curCiphers);

		Set<String> added = new LinkedHashSet<>(curNames);
		added.removeAll(baseNames);

		Set<String> removed = new LinkedHashSet<>(baseNames);
		removed.removeAll(curNames);

		if (!added.isEmpty()) {
			System.out.println("  Ciphers added:");
			for (String name : added) {
				System.out.println("    + " + name);
			}
		}
		if (!removed.isEmpty()) {
			System.out.println("  Ciphers removed:");
			for (String name : removed) {
				System.out.println("    - " + name);
			}
		}
		if (added.isEmpty() && removed.isEmpty()) {
			System.out.println("  Ciphers: unchanged (" + curNames.size() + " suites)");
		}
	}

	private Set<String> cipherNames(ICipherSuite[] ciphers) {
		Set<String> names = new LinkedHashSet<>();
		if (ciphers != null) {
			for (ICipherSuite c : ciphers) {
				names.add(c.getSuiteName());
			}
		}
		return names;
	}

	private HostSnapshot findHost(ScanSnapshot snapshot, String targetUrl) {
		for (HostSnapshot h : snapshot.getHosts()) {
			if (h.getTargetUrl().equals(targetUrl)) {
				return h;
			}
		}
		return null;
	}

	/** Entry point.
	 *  @param args optional baseline and current .dvscan file paths */
	public static final void main(String[] args) {
		try {
			File baselineFile;
			File currentFile;
			if (args.length >= 2) {
				baselineFile = new File(args[0]);
				currentFile = new File(args[1]);
			} else {
				baselineFile = new File("baseline.dvscan");
				currentFile = new File("current.dvscan");
			}
			new PrintScanDelta(baselineFile, currentFile);
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
