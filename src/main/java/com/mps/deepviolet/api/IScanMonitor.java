package com.mps.deepviolet.api;

import java.util.List;

/**
 * Pollable interface for monitoring scan progress.
 * Matches the BackgroundTask polling pattern for UI Timer integration.
 *
 * @author Milton Smith
 */
public interface IScanMonitor {

	/**
	 * Number of threads actively executing a section right now.
	 * @return active thread count
	 */
	int getActiveThreadCount();

	/**
	 * Number of threads in per-host section delay sleep.
	 * @return sleeping thread count
	 */
	int getSleepingThreadCount();

	/**
	 * Number of idle threads (waiting for work).
	 * @return idle thread count
	 */
	int getIdleThreadCount();

	/**
	 * Hosts completed so far.
	 * @return completed host count
	 */
	int getCompletedHostCount();

	/**
	 * Total hosts in the scan.
	 * @return total host count
	 */
	int getTotalHostCount();

	/**
	 * True while the scan is still running.
	 * @return true if the scan is running
	 */
	boolean isRunning();

	/**
	 * Snapshot of per-thread status.
	 * @return list of thread status snapshots
	 */
	List<IThreadStatus> getThreadStatuses();
}
