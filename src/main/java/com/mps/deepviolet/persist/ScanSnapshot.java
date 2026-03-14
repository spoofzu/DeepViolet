package com.mps.deepviolet.persist;

import java.util.ArrayList;
import java.util.List;

/**
 * Top-level persistence snapshot containing all scan results.
 *
 * @author Milton Smith
 */
public class ScanSnapshot {

	private int totalTargets;
	private int successCount;
	private int errorCount;
	private String scanId;
	private final List<HostSnapshot> hosts = new ArrayList<>();

	public int getTotalTargets() { return totalTargets; }
	public void setTotalTargets(int totalTargets) { this.totalTargets = totalTargets; }

	public int getSuccessCount() { return successCount; }
	public void setSuccessCount(int successCount) { this.successCount = successCount; }

	public int getErrorCount() { return errorCount; }
	public void setErrorCount(int errorCount) { this.errorCount = errorCount; }

	public String getScanId() { return scanId; }
	public void setScanId(String scanId) { this.scanId = scanId; }

	public List<HostSnapshot> getHosts() { return hosts; }

	public void addHost(HostSnapshot host) { hosts.add(host); }
}
