package com.mps.deepviolet.samples;

import java.net.URL;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import com.mps.deepviolet.api.ScanConfig;
import com.mps.deepviolet.api.TlsScanner;
import com.mps.deepviolet.api.ScanSection;
import com.mps.deepviolet.api.IScanMonitor;
import com.mps.deepviolet.api.IScanResult;
import com.mps.deepviolet.api.IScanListener;

/**
 * Demonstrate the scanning API.
 *
 * <p>Shows target specs with hostname, ScanConfig builder with
 * thread count and section delay, IScanListener for per-host
 * events, IScanMonitor polling loop (same Timer pattern as
 * {@link PrintBackgroundScan}), and per-host result iteration.</p>
 *
 * @author Milton Smith
 */
public class PrintScan {

	public static final void main(String[] args) {
		try {
			System.out.println("=== Scan Demo ===");
			System.out.println();

			// Target specs — hostname format
			List<String> targets = List.of(
				"github.com",
				"google.com:443",
				"https://example.com/"
			);

			System.out.println("Targets: " + targets);
			System.out.println();

			// Configure scan
			ScanConfig config = ScanConfig.builder()
				.threadCount(3)
				.sectionDelayMs(100)
				.perHostTimeoutMs(30000)
				.enabledSections(EnumSet.of(
					ScanSection.SESSION_INIT,
					ScanSection.CIPHER_ENUMERATION,
					ScanSection.CERTIFICATE_RETRIEVAL
				))
				.build();

			// Listener for per-host events
			IScanListener listener = new IScanListener() {
				@Override
				public void onHostStarted(URL url, int index, int total) {
					System.out.printf("[%d/%d] Starting: %s%n", index + 1, total, url);
				}

				@Override
				public void onSectionStarted(URL url, ScanSection section) {
					System.out.printf("  [section] %s: %s%n", url.getHost(), section.getDisplayName());
				}

				@Override
				public void onHostCompleted(IScanResult result, int completedCount, int total) {
					String status = result.isSuccess() ? "OK" : "FAILED";
					System.out.printf("[%d/%d] Completed: %s (%s, %dms)%n",
						completedCount, total, result.getURL(),
						status, result.getDuration().toMillis());
				}

				@Override
				public void onScanCompleted(List<IScanResult> results) {
					System.out.println();
					System.out.println("=== Scan Complete ===");
				}

				@Override
				public void onHostStatus(URL url, String message) {
					System.out.printf("  [status] %s: %s%n", url.getHost(), message);
				}
			};

			// Monitor polling in a background thread (same pattern as GUI Timer)
			IScanMonitor monitor = TlsScanner.getMonitor();
			Thread monitorThread = Thread.startVirtualThread(() -> {
				while (monitor.isRunning() || monitor.getCompletedHostCount() == 0) {
					System.out.printf("  [monitor] active=%d sleeping=%d idle=%d completed=%d/%d%n",
						monitor.getActiveThreadCount(),
						monitor.getSleepingThreadCount(),
						monitor.getIdleThreadCount(),
						monitor.getCompletedHostCount(),
						monitor.getTotalHostCount());
					try { Thread.sleep(500); } catch (InterruptedException e) { break; }
				}
			});

			// Run the scan
			List<IScanResult> results = TlsScanner.scan(targets, config, listener);

			monitorThread.interrupt();

			// Print results summary
			System.out.println();
			System.out.println("=== Results Summary ===");
			for (IScanResult result : results) {
				System.out.printf("  %s: success=%s sections=%s duration=%dms%n",
					result.getURL(),
					result.isSuccess(),
					result.getCompletedSections(),
					result.getDuration().toMillis());
				if (!result.isSuccess()) {
					System.out.printf("    error: %s%n", result.getError().getMessage());
				}
			}

			long successes = results.stream().filter(IScanResult::isSuccess).count();
			System.out.printf("%nTotal: %d hosts, %d succeeded, %d failed%n",
				results.size(), successes, results.size() - successes);

		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
