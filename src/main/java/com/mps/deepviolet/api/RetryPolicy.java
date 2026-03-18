package com.mps.deepviolet.api;

import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.concurrent.ThreadLocalRandom;

import com.mps.deepviolet.api.tls.TlsException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configurable retry policy with exponential backoff and jitter.
 * Retries transient {@link IOException} failures while respecting
 * cancellation and a wall-clock budget.
 *
 * @author Milton Smith
 */
public final class RetryPolicy {

	private static final Logger logger = LoggerFactory.getLogger(RetryPolicy.class);

	private final int maxRetries;
	private final long initialDelayMs;
	private final long maxDelayMs;
	private final long retryBudgetMs;

	private RetryPolicy(int maxRetries, long initialDelayMs, long maxDelayMs, long retryBudgetMs) {
		this.maxRetries = maxRetries;
		this.initialDelayMs = initialDelayMs;
		this.maxDelayMs = maxDelayMs;
		this.retryBudgetMs = retryBudgetMs;
	}

	/** Maximum number of retry attempts (0 = no retries).
	 *  @return max retries */
	public int getMaxRetries() { return maxRetries; }

	/** Initial delay before the first retry in milliseconds.
	 *  @return initial delay */
	public long getInitialDelayMs() { return initialDelayMs; }

	/** Maximum delay between retries in milliseconds.
	 *  @return max delay */
	public long getMaxDelayMs() { return maxDelayMs; }

	/** Total wall-clock budget for all retries in milliseconds.
	 *  @return retry budget */
	public long getRetryBudgetMs() { return retryBudgetMs; }

	/**
	 * Create a policy with default settings (3 retries, 500ms initial, 4s max, 15s budget).
	 * @return default retry policy
	 */
	public static RetryPolicy defaults() {
		return new RetryPolicy(3, 500, 4000, 15000);
	}

	/**
	 * Create a disabled policy (no retries).
	 * @return disabled retry policy
	 */
	public static RetryPolicy disabled() {
		return new RetryPolicy(0, 0, 0, 0);
	}

	/**
	 * Create a new builder.
	 * @return builder
	 */
	public static Builder builder() { return new Builder(); }

	/**
	 * Execute a task with retry. Retries on transient {@link IOException}.
	 * Does not retry {@link TlsException}, {@link RuntimeException}, or other non-IO errors.
	 *
	 * @param <T> return type
	 * @param task the callable to execute
	 * @param bg background task for cancellation checks, or null
	 * @return the task result
	 * @throws Exception the last exception if all retries exhausted, or immediate on non-retryable
	 */
	public <T> T execute(Callable<T> task, BackgroundTask bg) throws Exception {
		long startTime = System.currentTimeMillis();
		Exception lastException = null;

		for (int attempt = 0; attempt <= maxRetries; attempt++) {
			// Check cancellation before each attempt
			if (bg != null && bg.isCancelled()) {
				throw lastException != null ? lastException
						: new InterruptedException("Task cancelled before retry");
			}
			if (Thread.currentThread().isInterrupted()) {
				throw lastException != null ? lastException
						: new InterruptedException("Thread interrupted before retry");
			}

			try {
				return task.call();
			} catch (Exception e) {
				lastException = e;

				if (!isRetryable(e)) {
					throw e;
				}

				if (attempt >= maxRetries) {
					logger.warn("Exhausted {} retries: {}", maxRetries, e.getMessage());
					throw e;
				}

				// Compute delay with exponential backoff + jitter
				long baseDelay = Math.min(initialDelayMs * (1L << attempt), maxDelayMs);
				long jitter = ThreadLocalRandom.current().nextLong(0, Math.max(1, baseDelay / 2));
				long delay = baseDelay + jitter;

				// Check budget
				long elapsed = System.currentTimeMillis() - startTime;
				if (elapsed + delay > retryBudgetMs) {
					logger.warn("Retry budget exhausted after {} attempts ({}ms elapsed): {}",
							attempt + 1, elapsed, e.getMessage());
					throw e;
				}

				logger.debug("Retry {}/{} in {}ms after: {}", attempt + 1, maxRetries, delay, e.getMessage());

				try {
					Thread.sleep(delay);
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw lastException;
				}
			}
		}

		// Should not reach here, but satisfy compiler
		throw lastException != null ? lastException : new IllegalStateException("No attempts made");
	}

	/**
	 * Execute a void task with retry.
	 *
	 * @param task the runnable to execute
	 * @param bg background task for cancellation checks, or null
	 * @throws Exception the last exception if all retries exhausted
	 */
	public void executeVoid(RunnableWithException task, BackgroundTask bg) throws Exception {
		execute(() -> { task.run(); return null; }, bg);
	}

	/**
	 * Determine if an exception is retryable (transient IO failure).
	 * Walks the cause chain for wrapped exceptions.
	 */
	static boolean isRetryable(Throwable e) {
		if (e instanceof TlsException) return false;
		if (e instanceof RuntimeException) return false;
		if (e instanceof IOException) return true;

		// Walk cause chain for wrapped IOException (e.g., DeepVioletException wrapping IOException)
		Throwable cause = e.getCause();
		while (cause != null) {
			if (cause instanceof TlsException) return false;
			if (cause instanceof RuntimeException) return false;
			if (cause instanceof IOException) return true;
			cause = cause.getCause();
		}
		return false;
	}

	/**
	 * A runnable that can throw checked exceptions.
	 */
	@FunctionalInterface
	public interface RunnableWithException {
		/** Run the task.
		 *  @throws Exception on failure */
		void run() throws Exception;
	}

	/**
	 * Builder for {@link RetryPolicy}.
	 */
	public static final class Builder {

		private int maxRetries = 3;
		private long initialDelayMs = 500;
		private long maxDelayMs = 4000;
		private long retryBudgetMs = 15000;

		private Builder() {}

		/** Set maximum retries. Must be &ge; 0. 0 disables retry.
		 *  @param n max retries
		 *  @return this builder */
		public Builder maxRetries(int n) {
			if (n < 0) throw new IllegalArgumentException("maxRetries must be >= 0");
			this.maxRetries = n;
			return this;
		}

		/** Set initial delay in milliseconds. Must be &ge; 100.
		 *  @param ms initial delay
		 *  @return this builder */
		public Builder initialDelayMs(long ms) {
			if (ms < 100) throw new IllegalArgumentException("initialDelayMs must be >= 100");
			this.initialDelayMs = ms;
			return this;
		}

		/** Set maximum delay in milliseconds. Must be &ge; initialDelayMs.
		 *  @param ms max delay
		 *  @return this builder */
		public Builder maxDelayMs(long ms) {
			this.maxDelayMs = ms;
			return this;
		}

		/** Set total retry budget in milliseconds. Must be &ge; 1000.
		 *  @param ms retry budget
		 *  @return this builder */
		public Builder retryBudgetMs(long ms) {
			if (ms < 1000) throw new IllegalArgumentException("retryBudgetMs must be >= 1000");
			this.retryBudgetMs = ms;
			return this;
		}

		/** Build the policy.
		 *  @return built RetryPolicy */
		public RetryPolicy build() {
			if (maxDelayMs < initialDelayMs) {
				throw new IllegalArgumentException("maxDelayMs must be >= initialDelayMs");
			}
			return new RetryPolicy(maxRetries, initialDelayMs, maxDelayMs, retryBudgetMs);
		}
	}
}
