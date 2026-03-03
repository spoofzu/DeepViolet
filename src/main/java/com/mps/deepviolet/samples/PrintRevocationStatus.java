package com.mps.deepviolet.samples;

import java.net.URL;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IRevocationStatus;
import com.mps.deepviolet.api.IRevocationStatus.RevocationResult;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.IX509Certificate;

/**
 * Print certificate revocation status using all available mechanisms:
 * OCSP, CRL, OneCRL, OCSP Stapling, Must-Staple, and Certificate
 * Transparency (SCTs from embedded, TLS extension, and OCSP stapling).
 *
 * <p>Demonstrates all 25 {@link IRevocationStatus} methods.</p>
 */
public class PrintRevocationStatus {

	public PrintRevocationStatus() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);
		IX509Certificate cert = eng.getCertificate();

		System.out.println("=== Revocation Status for " + url + " ===");
		System.out.println();

		IRevocationStatus rev = cert.getRevocationStatus();
		if (rev == null) {
			System.out.println("Revocation information not available.");
			return;
		}

		System.out.println("Certificate: " + rev.getCertSubjectDN());
		System.out.println();

		// --- OCSP ---
		System.out.println("--- OCSP ---");
		RevocationResult ocspStatus = rev.getOcspStatus();
		System.out.println("Status:         " + ocspStatus);
		if (ocspStatus != RevocationResult.NOT_CHECKED) {
			System.out.println("Responder URL:  " + rev.getOcspResponderUrl());
			System.out.println("Response Time:  " + rev.getOcspResponseTimeMs() + " ms");
			System.out.println("This Update:    " + rev.getOcspThisUpdate());
			System.out.println("Next Update:    " + rev.getOcspNextUpdate());
			System.out.println("Signature Valid:" + rev.isOcspSignatureValid());
		}
		if (rev.getOcspErrorMessage() != null) {
			System.out.println("Error:          " + rev.getOcspErrorMessage());
		}
		System.out.println();

		// --- CRL ---
		System.out.println("--- CRL ---");
		RevocationResult crlStatus = rev.getCrlStatus();
		System.out.println("Status:         " + crlStatus);
		if (crlStatus != RevocationResult.NOT_CHECKED) {
			System.out.println("Dist. Point:    " + rev.getCrlDistributionPoint());
			System.out.println("Response Time:  " + rev.getCrlResponseTimeMs() + " ms");
			System.out.println("CRL Size:       " + rev.getCrlSizeBytes() + " bytes");
			System.out.println("This Update:    " + rev.getCrlThisUpdate());
			System.out.println("Next Update:    " + rev.getCrlNextUpdate());
		}
		if (rev.getCrlErrorMessage() != null) {
			System.out.println("Error:          " + rev.getCrlErrorMessage());
		}
		System.out.println();

		// --- OneCRL ---
		System.out.println("--- OneCRL ---");
		System.out.println("Status:         " + rev.getOneCrlStatus());
		if (rev.getOneCrlErrorMessage() != null) {
			System.out.println("Error:          " + rev.getOneCrlErrorMessage());
		}
		System.out.println();

		// --- OCSP Stapling ---
		System.out.println("--- OCSP Stapling ---");
		System.out.println("Present:        " + rev.isOcspStaplingPresent());
		if (rev.isOcspStaplingPresent()) {
			System.out.println("Stapled Status: " + rev.getStapledOcspStatus());
		}
		System.out.println();

		// --- Must-Staple ---
		System.out.println("--- Must-Staple ---");
		System.out.println("Present:        " + rev.isMustStaplePresent());
		if (rev.isMustStaplePresent() && !rev.isOcspStaplingPresent()) {
			System.out.println("WARNING: Must-Staple set but no stapled response!");
		}
		System.out.println();

		// --- Certificate Transparency SCTs ---
		System.out.println("--- Certificate Transparency (SCTs) ---");
		System.out.println("Total SCTs:     " + rev.getSctCount());

		int embedded = rev.getEmbeddedSctCount();
		System.out.println("Embedded:       " + embedded);
		if (embedded > 0) {
			for (String detail : rev.getEmbeddedSctDetails()) {
				System.out.println("  " + detail);
			}
		}

		int tlsExt = rev.getTlsExtensionSctCount();
		if (tlsExt < 0) {
			System.out.println("TLS Extension:  not available (Java limitation)");
		} else {
			System.out.println("TLS Extension:  " + tlsExt);
			if (tlsExt > 0) {
				for (String detail : rev.getTlsExtensionSctDetails()) {
					System.out.println("  " + detail);
				}
			}
		}

		int ocspStaple = rev.getOcspStaplingSctCount();
		System.out.println("OCSP Stapling:  " + ocspStaple);
		if (ocspStaple > 0) {
			for (String detail : rev.getOcspStaplingSctDetails()) {
				System.out.println("  " + detail);
			}
		}

		// Legacy: getSctDetails() returns all SCTs regardless of source
		String[] allDetails = rev.getSctDetails();
		if (allDetails != null && allDetails.length > 0) {
			System.out.println();
			System.out.println("All SCT details (legacy):");
			for (String detail : allDetails) {
				System.out.println("  " + detail);
			}
		}

		System.out.flush();
	}

	public static final void main(String[] args) {
		try {
			new PrintRevocationStatus();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
