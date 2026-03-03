package com.mps.deepviolet.samples;

import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import com.mps.deepviolet.api.BackgroundTask;
import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.ICipherSuite;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;
import com.mps.deepviolet.api.IX509Certificate;
import com.mps.deepviolet.api.tls.ClientHelloConfig;

/**
 * Demonstrate the {@link BackgroundTask} subclass pattern used by both
 * the DeepVioletTools GUI and CLI.
 *
 * <p>Extends {@code BackgroundTask}, overrides {@code doInBackground()},
 * uses the 4-argument {@link DeepVioletFactory#getEngine(ISession,
 * ISession.CIPHER_NAME_CONVENTION, BackgroundTask, Set)} overload
 * with protocol filtering (TLS 1.2 + TLS 1.3 only), and polls
 * {@link BackgroundTask#isWorking()} from the main thread.</p>
 */
public class PrintBackgroundScan extends BackgroundTask {

	private final URL url;

	public PrintBackgroundScan(URL url) {
		this.url = url;
	}

	@Override
	protected void doInBackground() throws Exception {

		// Initialize session
		setStatusBarMessage("Initializing session");
		ISession session = DeepVioletFactory.initializeSession(url);

		// Filter to TLS 1.2 and TLS 1.3 only
		Set<Integer> protocols = new HashSet<>();
		protocols.add(ClientHelloConfig.TLS_1_2);
		protocols.add(ClientHelloConfig.TLS_1_3);

		// Create engine with background task (this) and protocol filter
		setStatusBarMessage("Creating engine");
		IEngine eng = DeepVioletFactory.getEngine(session,
				CIPHER_NAME_CONVENTION.IANA, this, protocols);

		// Fetch certificate
		setStatusBarMessage("Fetching certificate");
		IX509Certificate cert = eng.getCertificate();
		setLargeStatusMessage("Subject: " + cert.getSubjectDN());

		// Enumerate cipher suites
		setStatusBarMessage("Enumerating cipher suites");
		ICipherSuite[] ciphers = eng.getCipherSuites();
		setLargeStatusMessage("Cipher suites found: " + ciphers.length);

		setStatusBarMessage("Done");
	}

	public static final void main(String[] args) {
		try {
			URL url = new URL("https://github.com/");

			System.out.println("=== Background Scan Demo ===");
			System.out.println("Target: " + url);
			System.out.println("Protocols: TLS 1.2, TLS 1.3 only");
			System.out.println();

			PrintBackgroundScan task = new PrintBackgroundScan(url);

			// Start the background thread
			task.start();

			// Poll for progress (same pattern as GUI Timer / CLI Timer)
			String lastStatus = "";
			boolean pauseDemo = false;
			long startTime = System.currentTimeMillis();
			while (task.isWorking()) {
				String currentStatus = task.getStatusBarMessage();
				if (!currentStatus.equals(lastStatus)) {
					System.out.println("[status] " + currentStatus);
					lastStatus = currentStatus;
				}

				String largeStatus = task.getLargeStatusMessage();
				if (largeStatus != null && !largeStatus.isEmpty()) {
					System.out.println("[result] " + largeStatus);
					task.setLargeStatusMessage("");
				}

				// Demonstrate pause/resume: pause after 1s, resume after 3s
				long elapsed = System.currentTimeMillis() - startTime;
				if (!pauseDemo && elapsed >= 1000) {
					System.out.println("[demo]   Pausing scan...");
					task.pause();
					Thread.sleep(3000);
					System.out.println("[demo]   Resuming scan...");
					task.unpause();
					pauseDemo = true;
				}

				Thread.sleep(100);
			}

			// Final status
			System.out.println("[status] " + task.getStatusBarMessage());
			String finalResult = task.getLargeStatusMessage();
			if (finalResult != null && !finalResult.isEmpty()) {
				System.out.println("[result] " + finalResult);
			}

			System.out.println();
			System.out.println("Scan complete.");

		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
