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
	private final int maxRetries;
	private final long initialRetryDelayMs;
	private final long maxRetryDelayMs;
	private final long retryBudgetMs;

	private ScanConfig(Builder builder) {
		this.threadCount = builder.threadCount;
		this.sectionDelayMs = builder.sectionDelayMs;
		this.perHostTimeoutMs = builder.perHostTimeoutMs;
		this.cipherNameConvention = builder.cipherNameConvention;
		this.enabledProtocols = builder.enabledProtocols == null
				? null
				: Collections.unmodifiableSet(builder.enabledProtocols);
		this.enabledSections = Collections.unmodifiableSet(builder.enabledSections);
		this.maxRetries = builder.maxRetries;
		this.initialRetryDelayMs = builder.initialRetryDelayMs;
		this.maxRetryDelayMs = builder.maxRetryDelayMs;
		this.retryBudgetMs = builder.retryBudgetMs;
	}

	/** Number of virtual threads. Controls overall scan tempo.
	 *  @return thread count */
	public int getThreadCount() { return threadCount; }

	/** Milliseconds to sleep between section requests on the same host.
	 *  @return section delay in milliseconds */
	public long getSectionDelayMs() { return sectionDelayMs; }

	/** Max time for a single host scan before it is marked as timed out.
	 *  @return per-host timeout in milliseconds */
	public long getPerHostTimeoutMs() { return perHostTimeoutMs; }

	/** Cipher suite naming convention.
	 *  @return naming convention */
	public CIPHER_NAME_CONVENTION getCipherNameConvention() { return cipherNameConvention; }

	/** Which TLS versions to probe, or null for all.
	 *  @return enabled protocols set, or null */
	public Set<Integer> getEnabledProtocols() { return enabledProtocols; }

	/** Which scan sections to execute.
	 *  @return enabled sections set */
	public Set<ScanSection> getEnabledSections() { return enabledSections; }

	/** Maximum number of retry attempts per section. 0 disables retry.
	 *  @return max retries */
	public int getMaxRetries() { return maxRetries; }

	/** Initial delay before the first retry in milliseconds.
	 *  @return initial retry delay */
	public long getInitialRetryDelayMs() { return initialRetryDelayMs; }

	/** Maximum delay between retries in milliseconds.
	 *  @return max retry delay */
	public long getMaxRetryDelayMs() { return maxRetryDelayMs; }

	/** Total wall-clock budget for retries per section in milliseconds.
	 *  @return retry budget */
	public long getRetryBudgetMs() { return retryBudgetMs; }

	/**
	 * Build a {@link RetryPolicy} from this config's retry settings.
	 * @return retry policy
	 */
	public RetryPolicy toRetryPolicy() {
		if (maxRetries == 0) {
			return RetryPolicy.disabled();
		}
		return RetryPolicy.builder()
				.maxRetries(maxRetries)
				.initialDelayMs(initialRetryDelayMs)
				.maxDelayMs(maxRetryDelayMs)
				.retryBudgetMs(retryBudgetMs)
				.build();
	}

	/** Create a new builder with default values.
	 *  @return new builder */
	public static Builder builder() { return new Builder(); }

	/** Create a config with all defaults.
	 *  @return default config */
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
		private int maxRetries = 3;
		private long initialRetryDelayMs = 500;
		private long maxRetryDelayMs = 4000;
		private long retryBudgetMs = 15000;

		private Builder() {}

		/** Set the number of concurrent virtual threads. Must be &ge; 1.
		 *  @param n thread count
		 *  @return this builder */
		public Builder threadCount(int n) {
			if (n < 1) throw new IllegalArgumentException("threadCount must be >= 1");
			this.threadCount = n;
			return this;
		}

		/** Set the per-host section delay in milliseconds. Must be &ge; 0.
		 *  @param ms delay in milliseconds
		 *  @return this builder */
		public Builder sectionDelayMs(long ms) {
			if (ms < 0) throw new IllegalArgumentException("sectionDelayMs must be >= 0");
			this.sectionDelayMs = ms;
			return this;
		}

		/** Set the per-host timeout in milliseconds. Must be &ge; 1000.
		 *  @param ms timeout in milliseconds
		 *  @return this builder */
		public Builder perHostTimeoutMs(long ms) {
			if (ms < 1000) throw new IllegalArgumentException("perHostTimeoutMs must be >= 1000");
			this.perHostTimeoutMs = ms;
			return this;
		}

		/** Set the cipher name convention.
		 *  @param c naming convention
		 *  @return this builder */
		public Builder cipherNameConvention(CIPHER_NAME_CONVENTION c) {
			if (c == null) throw new IllegalArgumentException("cipherNameConvention must not be null");
			this.cipherNameConvention = c;
			return this;
		}

		/** Set which TLS protocol versions to probe, or null for all.
		 *  @param protocols enabled protocol versions
		 *  @return this builder */
		public Builder enabledProtocols(Set<Integer> protocols) {
			this.enabledProtocols = protocols;
			return this;
		}

		/** Set which scan sections to execute.
		 *  @param sections enabled scan sections
		 *  @return this builder */
		public Builder enabledSections(Set<ScanSection> sections) {
			if (sections == null || sections.isEmpty()) {
				throw new IllegalArgumentException("enabledSections must not be null or empty");
			}
			this.enabledSections = EnumSet.copyOf(sections);
			return this;
		}

		/** Set maximum retries per section. Must be &ge; 0. 0 disables retry.
		 *  @param n max retries
		 *  @return this builder */
		public Builder maxRetries(int n) {
			if (n < 0) throw new IllegalArgumentException("maxRetries must be >= 0");
			this.maxRetries = n;
			return this;
		}

		/** Set initial retry delay in milliseconds. Must be &ge; 100.
		 *  @param ms initial retry delay
		 *  @return this builder */
		public Builder initialRetryDelayMs(long ms) {
			if (ms < 100) throw new IllegalArgumentException("initialRetryDelayMs must be >= 100");
			this.initialRetryDelayMs = ms;
			return this;
		}

		/** Set maximum retry delay in milliseconds. Must be &ge; initialRetryDelayMs.
		 *  @param ms max retry delay
		 *  @return this builder */
		public Builder maxRetryDelayMs(long ms) {
			this.maxRetryDelayMs = ms;
			return this;
		}

		/** Set total retry budget per section in milliseconds. Must be &ge; 1000.
		 *  @param ms retry budget
		 *  @return this builder */
		public Builder retryBudgetMs(long ms) {
			if (ms < 1000) throw new IllegalArgumentException("retryBudgetMs must be >= 1000");
			this.retryBudgetMs = ms;
			return this;
		}

		/** Build the configuration.
		 *  @return built ScanConfig */
		public ScanConfig build() {
			if (maxRetries > 0 && maxRetryDelayMs < initialRetryDelayMs) {
				throw new IllegalArgumentException("maxRetryDelayMs must be >= initialRetryDelayMs");
			}
			return new ScanConfig(this);
		}
	}
}
