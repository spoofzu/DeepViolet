package com.mps.deepviolet.api;

import java.util.List;

/**
 * Pollable interface for monitoring scan progress.
 * Matches the BackgroundTask polling pattern for UI Timer integration.
 *
 * @author Milton Smith
 */
public interface IScanMonitor {

	/** Number of threads actively executing a section right now. */
	int getActiveThreadCount();

	/** Number of threads in per-host section delay sleep. */
	int getSleepingThreadCount();

	/** Number of idle threads (waiting for work). */
	int getIdleThreadCount();

	/** Hosts completed so far. */
	int getCompletedHostCount();

	/** Total hosts in the scan. */
	int getTotalHostCount();

	/** True while the scan is still running. */
	boolean isRunning();

	/** Snapshot of per-thread status. */
	List<IThreadStatus> getThreadStatuses();
}
