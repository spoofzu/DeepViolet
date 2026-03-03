package com.mps.deepviolet.samples;

import java.net.URL;
import java.util.List;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.IX509Certificate;
import com.mps.deepviolet.api.IX509Certificate.TrustState;
import com.mps.deepviolet.api.IX509Certificate.ValidState;

/**
 * Walk the full server certificate chain and print detailed information
 * for each certificate.
 *
 * <p>Demonstrates all {@link IX509Certificate} methods: subject/issuer DN,
 * serial number, version, signing algorithm (name and OID), public key
 * (algorithm, size, EC curve), fingerprint, validity (state, dates, days
 * until expiration), trust state, self-signed/root flags, Subject Alternative
 * Names, and critical/non-critical OID extensions.</p>
 */
public class PrintCertificateChain {

	public PrintCertificateChain() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);
		IX509Certificate cert = eng.getCertificate();

		IX509Certificate[] chain = cert.getCertificateChain();
		System.out.println("=== Certificate Chain for " + url + " ===");
		System.out.println("Chain length: " + chain.length);
		System.out.println();

		for (int i = 0; i < chain.length; i++) {
			IX509Certificate c = chain[i];

			// Determine role
			String role;
			if (i == 0) {
				role = "End-Entity";
			} else if (c.isSelfSignedCertificate()) {
				role = c.isJavaRootCertificate() ? "Java Root CA" : "Self-Signed CA";
			} else {
				role = "Intermediate CA";
			}

			System.out.println("--- NODE" + i + " (" + role + ") ---");

			// Identity
			System.out.println("Subject DN:      " + c.getSubjectDN());
			System.out.println("Issuer DN:       " + c.getIssuerDN());
			System.out.println("Serial Number:   " + c.getCertificateSerialNumber());
			System.out.println("Version:         " + c.getCertificateVersion());

			// Signing
			System.out.println("Signing Algo:    " + c.getSigningAlgorithm());
			System.out.println("Signing OID:     " + c.getSigningAlgorithmOID());

			// Public key
			System.out.println("PubKey Algo:     " + c.getPublicKeyAlgorithm());
			System.out.println("PubKey Size:     " + c.getPublicKeySize() + " bits");
			if (c.getPublicKeyCurve() != null) {
				System.out.println("PubKey Curve:    " + c.getPublicKeyCurve());
			}

			// Fingerprint
			System.out.println("Fingerprint:     " + c.getCertificateFingerPrint());

			// Validity
			ValidState vs = c.getValidityState();
			System.out.println("Validity:        " + vs);
			System.out.println("Not Before:      " + c.getNotValidBefore());
			System.out.println("Not After:       " + c.getNotValidAfter());
			long daysLeft = c.getDaysUntilExpiration();
			if (daysLeft < 0) {
				System.out.println("Expiration:      EXPIRED " + Math.abs(daysLeft) + " days ago");
			} else {
				System.out.println("Days Left:       " + daysLeft);
			}

			// Trust
			TrustState ts = c.getTrustState();
			System.out.println("Trust State:     " + ts);
			System.out.println("Self-Signed:     " + c.isSelfSignedCertificate());
			System.out.println("Java Root:       " + c.isJavaRootCertificate());

			// SANs (typically only on end-entity)
			List<String> sans = c.getSubjectAlternativeNames();
			if (sans != null && !sans.isEmpty()) {
				System.out.println("SANs (" + sans.size() + "):");
				for (String san : sans) {
					System.out.println("  " + san);
				}
			}

			// Non-critical OID extensions
			String[] nonCritOids = c.getNonCritOIDProperties();
			if (nonCritOids.length > 0) {
				System.out.println("Non-Critical OIDs:");
				for (String oid : nonCritOids) {
					System.out.println("  " + oid + " = " + c.getNonCritPropertyValue(oid));
				}
			}

			// Critical OID extensions
			String[] critOids = c.getCritOIDProperties();
			if (critOids.length > 0) {
				System.out.println("Critical OIDs:");
				for (String oid : critOids) {
					System.out.println("  " + oid + " = " + c.getCritPropertyValue(oid));
				}
			}

			System.out.println();
		}

		System.out.flush();
	}

	public static final void main(String[] args) {
		try {
			new PrintCertificateChain();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
