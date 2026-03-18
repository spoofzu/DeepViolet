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

	/**
	 * The URL that was scanned.
	 * @return the scanned URL
	 */
	URL getURL();

	/**
	 * True if the scan completed without fatal error.
	 * @return true on success
	 */
	boolean isSuccess();

	/**
	 * The session, or null on failure.
	 * @return the session
	 */
	ISession getSession();

	/**
	 * The engine, or null on failure.
	 * @return the engine
	 */
	IEngine getEngine();

	/**
	 * The error, or null on success.
	 * @return the error
	 */
	DeepVioletException getError();

	/**
	 * When the scan started.
	 * @return the start time
	 */
	Instant getStartTime();

	/**
	 * When the scan ended.
	 * @return the end time
	 */
	Instant getEndTime();

	/**
	 * How long the scan took.
	 * @return the scan duration
	 */
	Duration getDuration();

	/**
	 * Which sections completed successfully for this host.
	 * @return set of completed sections
	 */
	Set<ScanSection> getCompletedSections();

	/**
	 * Which sections failed after all retry attempts for this host.
	 * @return set of failed sections
	 */
	Set<ScanSection> getFailedSections();
}
