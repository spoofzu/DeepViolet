package com.mps.deepviolet.samples;

import java.net.URL;
import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;

/**
 * Enumerate server cipher suites grouped by handshake protocol.
 *
 * <p>Demonstrates the {@link CIPHER_NAME_CONVENTION} enum by creating
 * two engines — one with IANA names and one with OpenSSL names — and
 * printing both side by side. Also groups ciphers by
 * {@link ICipherSuite#getHandshakeProtocol()} and shows
 * {@link ICipherSuite#getStrengthEvaluation()}.</p>
 */
public class PrintCipherSuites {

	public PrintCipherSuites() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);

		// --- IANA names (default convention) ---
		IEngine ianaEng = DeepVioletFactory.getEngine(session, CIPHER_NAME_CONVENTION.IANA);
		ICipherSuite[] ianaCiphers = ianaEng.getCipherSuites();

		System.out.println("=== Cipher Suites for " + url + " ===");
		System.out.println("Total ciphers reported: " + ianaCiphers.length);
		System.out.println();

		// Group by handshake protocol
		Map<String, List<ICipherSuite>> grouped = new LinkedHashMap<>();
		for (ICipherSuite cipher : ianaCiphers) {
			grouped.computeIfAbsent(cipher.getHandshakeProtocol(),
					k -> new ArrayList<>()).add(cipher);
		}

		System.out.println("--- IANA Names (grouped by protocol) ---");
		for (Map.Entry<String, List<ICipherSuite>> entry : grouped.entrySet()) {
			System.out.println();
			System.out.println("[" + entry.getKey() + "]");
			for (ICipherSuite cipher : entry.getValue()) {
				System.out.println("  " + cipher.getSuiteName()
						+ " (" + cipher.getStrengthEvaluation() + ")");
			}
		}

		// --- OpenSSL names ---
		System.out.println();
		System.out.println("--- OpenSSL Names ---");
		IEngine opensslEng = DeepVioletFactory.getEngine(session, CIPHER_NAME_CONVENTION.OpenSSL);
		ICipherSuite[] opensslCiphers = opensslEng.getCipherSuites();
		for (ICipherSuite cipher : opensslCiphers) {
			System.out.println("  " + cipher.getSuiteName()
					+ " (" + cipher.getStrengthEvaluation()
					+ ", " + cipher.getHandshakeProtocol() + ")");
		}

		System.out.flush();
	}

	public static final void main(String[] args) {
		try {
			new PrintCipherSuites();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
