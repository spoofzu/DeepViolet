package com.mps.deepviolet.api;

import java.net.URL;

/**
 * Per-thread snapshot for UI display during scanning.
 *
 * @author Milton Smith
 */
public interface IThreadStatus {

	/**
	 * Thread identifier (e.g., "dv-scan-1").
	 * @return the thread name
	 */
	String getThreadName();

	/**
	 * Current state.
	 * @return the thread state
	 */
	ThreadState getState();

	/**
	 * Host this thread is scanning, or null if idle.
	 * @return the current host URL
	 */
	URL getCurrentHost();

	/**
	 * Section this thread is executing, or null if idle/sleeping.
	 * @return the current scan section
	 */
	ScanSection getCurrentSection();

	/**
	 * Current status message from the engine.
	 * @return the status message
	 */
	String getStatusMessage();
}
