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

	/** A host scan is starting. */
	default void onHostStarted(URL url, int index, int total) {}

	/** A section is starting on a host. */
	default void onSectionStarted(URL url, ScanSection section) {}

	/** A section completed on a host. */
	default void onSectionCompleted(URL url, ScanSection section) {}

	/** A host scan completed (success or failure). */
	default void onHostCompleted(IScanResult result, int completedCount, int total) {}

	/** All hosts scanned. */
	default void onScanCompleted(List<IScanResult> results) {}

	/** Status text from the scanning engine for a host (bridges BackgroundTask). */
	default void onHostStatus(URL url, String message) {}
}
