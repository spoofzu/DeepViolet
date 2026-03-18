package com.mps.deepviolet.api;

import java.net.URL;
import java.util.List;

/**
 * Callback-based listener for scan events.
 * All methods have default no-op implementations.
 *
 * @author Milton Smith
 */
public interface IScanListener {

	/**
	 * A host scan is starting.
	 * @param url the host URL being scanned
	 * @param index zero-based index of this host in the scan
	 * @param total total number of hosts in the scan
	 */
	default void onHostStarted(URL url, int index, int total) {}

	/**
	 * A section is starting on a host.
	 * @param url the host URL
	 * @param section the section that is starting
	 */
	default void onSectionStarted(URL url, ScanSection section) {}

	/**
	 * A section completed on a host.
	 * @param url the host URL
	 * @param section the section that completed
	 */
	default void onSectionCompleted(URL url, ScanSection section) {}

	/**
	 * A host scan completed (success or failure).
	 * @param result the per-host scan result
	 * @param completedCount number of hosts completed so far
	 * @param total total number of hosts in the scan
	 */
	default void onHostCompleted(IScanResult result, int completedCount, int total) {}

	/**
	 * All hosts scanned.
	 * @param results list of all per-host scan results
	 */
	default void onScanCompleted(List<IScanResult> results) {}

	/**
	 * A section failed after all retry attempts on a host.
	 * @param url the host URL
	 * @param section the section that failed
	 * @param attempts number of attempts made (1 = no retries)
	 * @param cause the last exception
	 */
	default void onSectionFailed(URL url, ScanSection section, int attempts, Exception cause) {}

	/**
	 * Status text from the scanning engine for a host (bridges BackgroundTask).
	 * @param url the host URL
	 * @param message the status message
	 */
	default void onHostStatus(URL url, String message) {}
}
