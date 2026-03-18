package com.mps.deepviolet.persist;

import java.util.ArrayList;
import java.util.List;

/**
 * Top-level persistence snapshot containing all scan results.
 *
 * @author Milton Smith
 */
public class ScanSnapshot {

	/** Creates an empty snapshot. */
	public ScanSnapshot() {}

	private int totalTargets;
	private int successCount;
	private int errorCount;
	private String scanId;
	private final List<HostSnapshot> hosts = new ArrayList<>();

	/** Returns total number of targets scanned.
	 *  @return total targets */
	public int getTotalTargets() { return totalTargets; }
	/** Sets total number of targets.
	 *  @param totalTargets total targets */
	public void setTotalTargets(int totalTargets) { this.totalTargets = totalTargets; }

	/** Returns the number of successful scans.
	 *  @return success count */
	public int getSuccessCount() { return successCount; }
	/** Sets the success count.
	 *  @param successCount success count */
	public void setSuccessCount(int successCount) { this.successCount = successCount; }

	/** Returns the number of failed scans.
	 *  @return error count */
	public int getErrorCount() { return errorCount; }
	/** Sets the error count.
	 *  @param errorCount error count */
	public void setErrorCount(int errorCount) { this.errorCount = errorCount; }

	/** Returns the scan identifier (SHA-256 hash of the saved file).
	 *  @return scan ID */
	public String getScanId() { return scanId; }
	/** Sets the scan identifier.
	 *  @param scanId scan ID */
	public void setScanId(String scanId) { this.scanId = scanId; }

	/** Returns the list of per-host snapshots.
	 *  @return host snapshots */
	public List<HostSnapshot> getHosts() { return hosts; }

	/** Adds a host snapshot.
	 *  @param host the host snapshot to add */
	public void addHost(HostSnapshot host) { hosts.add(host); }
}
