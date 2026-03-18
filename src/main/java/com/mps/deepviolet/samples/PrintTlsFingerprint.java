package com.mps.deepviolet.samples;

import java.net.URL;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.fingerprint.TlsBehaviorProbes;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint;
import com.mps.deepviolet.api.fingerprint.TlsServerFingerprint.FingerprintComponents;

/**
 * Compute and analyze a TLS server fingerprint.
 *
 * <p>Demonstrates {@link IEngine#getTlsFingerprint()},
 * {@link TlsServerFingerprint#parse(String)},
 * {@link TlsServerFingerprint#summarize(String)},
 * {@link TlsServerFingerprint#isNoTlsSupport(String)},
 * {@link FingerprintComponents} probe iteration, and
 * {@link TlsBehaviorProbes#getProbeDescription(int)}.</p>
 */
public class PrintTlsFingerprint {

	public PrintTlsFingerprint() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);

		System.out.println("=== TLS Fingerprint for " + url + " ===");
		System.out.println();

		String fingerprint = eng.getTlsFingerprint();

		if (fingerprint == null) {
			System.out.println("Fingerprint not available.");
			return;
		}

		System.out.println("Raw Fingerprint: " + fingerprint);
		System.out.println("Length:          " + fingerprint.length() + " chars");
		System.out.println("Summary:         " + TlsServerFingerprint.summarize(fingerprint));
		System.out.println();

		// Check for no TLS support
		if (TlsServerFingerprint.isNoTlsSupport(fingerprint)) {
			System.out.println("WARNING: All probes failed — server may not support TLS.");
			return;
		}

		// Parse into components
		FingerprintComponents components = TlsServerFingerprint.parse(fingerprint);
		if (components == null) {
			System.out.println("Could not parse fingerprint.");
			return;
		}

		// Iterate the 10 behavior probes
		System.out.println("--- Behavior Probes ---");
		String[] probeCodes = components.getProbeCodes();
		System.out.println("Probe codes: " + probeCodes.length);
		System.out.println();

		for (int i = 1; i <= TlsBehaviorProbes.PROBE_COUNT; i++) {
			String code = components.getProbeCode(i);
			boolean success = components.probeSucceeded(i);
			String description = TlsBehaviorProbes.getProbeDescription(i);

			System.out.printf("Probe %2d: code=%s  success=%-5s  %s%n",
					i, code, success, description);

			if (success) {
				System.out.printf("          cipher=%s  version=%s  extension=%s%n",
						components.getCipherChar(i),
						components.getVersionChar(i),
						components.getExtensionChar(i));
			}
		}

		System.out.flush();
	}

	public static final void main(String[] args) {
		try {
			new PrintTlsFingerprint();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
