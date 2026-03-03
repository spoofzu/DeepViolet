package com.mps.deepviolet.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Package-private implementation of {@link IScanMonitor}.
 * Thread-safe; updated by the scanner as threads transition.
 */
class ScanMonitor implements IScanMonitor {

	private final ConcurrentHashMap<String, ThreadStatus> threads = new ConcurrentHashMap<>();
	private final AtomicInteger completedHostCount = new AtomicInteger(0);
	private volatile int totalHostCount;
	private final AtomicBoolean running = new AtomicBoolean(false);

	ScanMonitor() {}

	@Override
	public int getActiveThreadCount() {
		int count = 0;
		for (ThreadStatus ts : threads.values()) {
			if (ts.getState() == ThreadState.EXECUTING) count++;
		}
		return count;
	}

	@Override
	public int getSleepingThreadCount() {
		int count = 0;
		for (ThreadStatus ts : threads.values()) {
			if (ts.getState() == ThreadState.SLEEPING) count++;
		}
		return count;
	}

	@Override
	public int getIdleThreadCount() {
		int count = 0;
		for (ThreadStatus ts : threads.values()) {
			if (ts.getState() == ThreadState.IDLE) count++;
		}
		return count;
	}

	@Override
	public int getCompletedHostCount() { return completedHostCount.get(); }

	@Override
	public int getTotalHostCount() { return totalHostCount; }

	@Override
	public boolean isRunning() { return running.get(); }

	@Override
	public List<IThreadStatus> getThreadStatuses() {
		return Collections.unmodifiableList(new ArrayList<>(threads.values()));
	}

	// Package-private mutators

	ThreadStatus getOrCreateThread(String threadName) {
		return threads.computeIfAbsent(threadName, ThreadStatus::new);
	}

	void incrementCompleted() { completedHostCount.incrementAndGet(); }

	void setTotalHostCount(int total) { this.totalHostCount = total; }

	void setRunning(boolean running) { this.running.set(running); }

	void reset() {
		threads.clear();
		completedHostCount.set(0);
		totalHostCount = 0;
		running.set(false);
	}
}
