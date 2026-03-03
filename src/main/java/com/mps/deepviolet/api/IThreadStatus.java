package com.mps.deepviolet.api;

import java.net.URL;

/**
 * Per-thread snapshot for UI display during scanning.
 *
 * @author Milton Smith
 */
public interface IThreadStatus {

	/** Thread identifier (e.g., "dv-scan-1"). */
	String getThreadName();

	/** Current state. */
	ThreadState getState();

	/** Host this thread is scanning, or null if idle. */
	URL getCurrentHost();

	/** Section this thread is executing, or null if idle/sleeping. */
	ScanSection getCurrentSection();

	/** Current status message from the engine. */
	String getStatusMessage();
}
