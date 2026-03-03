package com.mps.deepviolet.api;

import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * Package-private implementation of {@link IScanResult}.
 */
class ScanResult implements IScanResult {

	private final URL url;
	private ISession session;
	private IEngine engine;
	private DeepVioletException error;
	private Instant startTime;
	private Instant endTime;
	private final Set<ScanSection> completedSections = EnumSet.noneOf(ScanSection.class);

	ScanResult(URL url) {
		this.url = url;
	}

	@Override public URL getURL() { return url; }

	@Override public boolean isSuccess() { return error == null; }

	@Override public ISession getSession() { return session; }

	@Override public IEngine getEngine() { return engine; }

	@Override public DeepVioletException getError() { return error; }

	@Override public Instant getStartTime() { return startTime; }

	@Override public Instant getEndTime() { return endTime; }

	@Override
	public Duration getDuration() {
		if (startTime == null || endTime == null) return Duration.ZERO;
		return Duration.between(startTime, endTime);
	}

	@Override
	public Set<ScanSection> getCompletedSections() {
		return Collections.unmodifiableSet(EnumSet.copyOf(
				completedSections.isEmpty() ? EnumSet.noneOf(ScanSection.class) : completedSections));
	}

	void setSession(ISession session) { this.session = session; }
	void setEngine(IEngine engine) { this.engine = engine; }
	void setError(DeepVioletException error) { this.error = error; }
	void setStartTime(Instant startTime) { this.startTime = startTime; }
	void setEndTime(Instant endTime) { this.endTime = endTime; }
	void addCompletedSection(ScanSection section) { completedSections.add(section); }
}
