package com.mps.deepviolet.api;

import java.net.URL;

/**
 * Package-private implementation of {@link IThreadStatus}.
 */
class ThreadStatus implements IThreadStatus {

	private final String threadName;
	private volatile ThreadState state = ThreadState.IDLE;
	private volatile URL currentHost;
	private volatile ScanSection currentSection;
	private volatile String statusMessage = "";

	ThreadStatus(String threadName) {
		this.threadName = threadName;
	}

	@Override public String getThreadName() { return threadName; }
	@Override public ThreadState getState() { return state; }
	@Override public URL getCurrentHost() { return currentHost; }
	@Override public ScanSection getCurrentSection() { return currentSection; }
	@Override public String getStatusMessage() { return statusMessage; }

	void setState(ThreadState state) { this.state = state; }
	void setCurrentHost(URL currentHost) { this.currentHost = currentHost; }
	void setCurrentSection(ScanSection currentSection) { this.currentSection = currentSection; }
	void setStatusMessage(String statusMessage) { this.statusMessage = statusMessage; }

	void setIdle() {
		this.state = ThreadState.IDLE;
		this.currentHost = null;
		this.currentSection = null;
		this.statusMessage = "";
	}
}
