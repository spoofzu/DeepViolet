package com.mps.deepviolet.api;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import com.mps.deepviolet.api.ISession.CIPHER_NAME_CONVENTION;

/**
 * Configuration for TLS scanning.
 * Use {@link #builder()} to create instances.
 *
 * @author Milton Smith
 */
public final class ScanConfig {

	private final int threadCount;
	private final long sectionDelayMs;
	private final long perHostTimeoutMs;
	private final CIPHER_NAME_CONVENTION cipherNameConvention;
	private final Set<Integer> enabledProtocols;
	private final Set<ScanSection> enabledSections;

	private ScanConfig(Builder builder) {
		this.threadCount = builder.threadCount;
		this.sectionDelayMs = builder.sectionDelayMs;
		this.perHostTimeoutMs = builder.perHostTimeoutMs;
		this.cipherNameConvention = builder.cipherNameConvention;
		this.enabledProtocols = builder.enabledProtocols == null
				? null
				: Collections.unmodifiableSet(builder.enabledProtocols);
		this.enabledSections = Collections.unmodifiableSet(builder.enabledSections);
	}

	/** Number of virtual threads. Controls overall scan tempo. */
	public int getThreadCount() { return threadCount; }

	/** Milliseconds to sleep between section requests on the same host. */
	public long getSectionDelayMs() { return sectionDelayMs; }

	/** Max time for a single host scan before it's marked as timed out. */
	public long getPerHostTimeoutMs() { return perHostTimeoutMs; }

	/** Cipher suite naming convention. */
	public CIPHER_NAME_CONVENTION getCipherNameConvention() { return cipherNameConvention; }

	/** Which TLS versions to probe, or null for all. */
	public Set<Integer> getEnabledProtocols() { return enabledProtocols; }

	/** Which scan sections to execute. */
	public Set<ScanSection> getEnabledSections() { return enabledSections; }

	/** Create a new builder with default values. */
	public static Builder builder() { return new Builder(); }

	/** Create a config with all defaults. */
	public static ScanConfig defaults() { return builder().build(); }

	/**
	 * Builder for {@link ScanConfig}.
	 */
	public static final class Builder {

		private int threadCount = 10;
		private long sectionDelayMs = 200;
		private long perHostTimeoutMs = 60000;
		private CIPHER_NAME_CONVENTION cipherNameConvention = CIPHER_NAME_CONVENTION.IANA;
		private Set<Integer> enabledProtocols = null;
		private Set<ScanSection> enabledSections = EnumSet.allOf(ScanSection.class);

		private Builder() {}

		/** Set the number of concurrent virtual threads. Must be &ge; 1. */
		public Builder threadCount(int n) {
			if (n < 1) throw new IllegalArgumentException("threadCount must be >= 1");
			this.threadCount = n;
			return this;
		}

		/** Set the per-host section delay in milliseconds. Must be &ge; 0. */
		public Builder sectionDelayMs(long ms) {
			if (ms < 0) throw new IllegalArgumentException("sectionDelayMs must be >= 0");
			this.sectionDelayMs = ms;
			return this;
		}

		/** Set the per-host timeout in milliseconds. Must be &ge; 1000. */
		public Builder perHostTimeoutMs(long ms) {
			if (ms < 1000) throw new IllegalArgumentException("perHostTimeoutMs must be >= 1000");
			this.perHostTimeoutMs = ms;
			return this;
		}

		/** Set the cipher name convention. */
		public Builder cipherNameConvention(CIPHER_NAME_CONVENTION c) {
			if (c == null) throw new IllegalArgumentException("cipherNameConvention must not be null");
			this.cipherNameConvention = c;
			return this;
		}

		/** Set which TLS protocol versions to probe, or null for all. */
		public Builder enabledProtocols(Set<Integer> protocols) {
			this.enabledProtocols = protocols;
			return this;
		}

		/** Set which scan sections to execute. */
		public Builder enabledSections(Set<ScanSection> sections) {
			if (sections == null || sections.isEmpty()) {
				throw new IllegalArgumentException("enabledSections must not be null or empty");
			}
			this.enabledSections = EnumSet.copyOf(sections);
			return this;
		}

		/** Build the configuration. */
		public ScanConfig build() {
			return new ScanConfig(this);
		}
	}
}
