package com.mps.deepviolet.api;

import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;

/**
 * Per-host result from a scan with section-level detail.
 *
 * @author Milton Smith
 */
public interface IScanResult {

	/** The URL that was scanned. */
	URL getURL();

	/** True if the scan completed without fatal error. */
	boolean isSuccess();

	/** The session, or null on failure. */
	ISession getSession();

	/** The engine, or null on failure. */
	IEngine getEngine();

	/** The error, or null on success. */
	DeepVioletException getError();

	/** When the scan started. */
	Instant getStartTime();

	/** When the scan ended. */
	Instant getEndTime();

	/** How long the scan took. */
	Duration getDuration();

	/** Which sections completed successfully for this host. */
	Set<ScanSection> getCompletedSections();
}
