package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import com.mps.deepviolet.api.tls.TlsException;

import org.junit.jupiter.api.Test;

/**
 * Tests for {@link RetryPolicy}.
 */
class RetryPolicyTest {

	@Test
	void succeedsFirstAttempt() throws Exception {
		RetryPolicy policy = RetryPolicy.defaults();
		String result = policy.execute(() -> "ok", null);
		assertEquals("ok", result);
	}

	@Test
	void succeedsAfterTransientFailure() throws Exception {
		RetryPolicy policy = RetryPolicy.builder()
				.maxRetries(3)
				.initialDelayMs(100)
				.maxDelayMs(200)
				.retryBudgetMs(5000)
				.build();

		AtomicInteger attempts = new AtomicInteger(0);
		String result = policy.execute(() -> {
			if (attempts.incrementAndGet() < 3) {
				throw new IOException("transient");
			}
			return "recovered";
		}, null);

		assertEquals("recovered", result);
		assertEquals(3, attempts.get());
	}

	@Test
	void exhaustsRetriesThrowsLast() {
		RetryPolicy policy = RetryPolicy.builder()
				.maxRetries(2)
				.initialDelayMs(100)
				.maxDelayMs(200)
				.retryBudgetMs(5000)
				.build();

		IOException thrown = assertThrows(IOException.class, () ->
			policy.execute(() -> { throw new IOException("persistent"); }, null)
		);
		assertEquals("persistent", thrown.getMessage());
	}

	@Test
	void respectsBudget() {
		// Budget of 1s with 500ms initial delay means at most 1-2 retries
		RetryPolicy policy = RetryPolicy.builder()
				.maxRetries(10)
				.initialDelayMs(500)
				.maxDelayMs(500)
				.retryBudgetMs(1000)
				.build();

		AtomicInteger attempts = new AtomicInteger(0);
		long start = System.currentTimeMillis();

		assertThrows(IOException.class, () ->
			policy.execute(() -> {
				attempts.incrementAndGet();
				throw new IOException("fail");
			}, null)
		);

		long elapsed = System.currentTimeMillis() - start;
		// Should not exceed budget by much
		assertTrue(elapsed < 3000, "Should respect budget; elapsed=" + elapsed + "ms");
		// Should have attempted more than 1 but fewer than maxRetries
		assertTrue(attempts.get() < 10, "Should stop before exhausting all retries; attempts=" + attempts.get());
	}

	@Test
	void doesNotRetryRuntimeException() {
		RetryPolicy policy = RetryPolicy.defaults();

		AtomicInteger attempts = new AtomicInteger(0);
		assertThrows(IllegalArgumentException.class, () ->
			policy.execute(() -> {
				attempts.incrementAndGet();
				throw new IllegalArgumentException("bad input");
			}, null)
		);
		assertEquals(1, attempts.get(), "Should not retry RuntimeException");
	}

	@Test
	void doesNotRetryTlsException() {
		RetryPolicy policy = RetryPolicy.defaults();

		AtomicInteger attempts = new AtomicInteger(0);
		assertThrows(TlsException.class, () ->
			policy.execute(() -> {
				attempts.incrementAndGet();
				throw new TlsException("handshake_failure");
			}, null)
		);
		assertEquals(1, attempts.get(), "Should not retry TlsException");
	}

	@Test
	void retriesWrappedIOException() throws Exception {
		RetryPolicy policy = RetryPolicy.builder()
				.maxRetries(2)
				.initialDelayMs(100)
				.maxDelayMs(200)
				.retryBudgetMs(5000)
				.build();

		AtomicInteger attempts = new AtomicInteger(0);
		String result = policy.execute(() -> {
			if (attempts.incrementAndGet() == 1) {
				throw new DeepVioletException("wrapped", new ConnectException("refused"));
			}
			return "ok";
		}, null);

		assertEquals("ok", result);
		assertEquals(2, attempts.get());
	}

	@Test
	void respectsCancellationBeforeFirstAttempt() {
		RetryPolicy policy = RetryPolicy.builder()
				.maxRetries(5)
				.initialDelayMs(100)
				.maxDelayMs(200)
				.retryBudgetMs(5000)
				.build();

		BackgroundTask bg = new BackgroundTask();
		bg.cancel();

		AtomicInteger attempts = new AtomicInteger(0);
		// Cancelled before first attempt — task is never called
		assertThrows(InterruptedException.class, () ->
			policy.execute(() -> {
				attempts.incrementAndGet();
				throw new IOException("fail");
			}, bg)
		);
		assertEquals(0, attempts.get(), "Should not attempt when already cancelled");
	}

	@Test
	void respectsCancellationBetweenRetries() throws Exception {
		RetryPolicy policy = RetryPolicy.builder()
				.maxRetries(5)
				.initialDelayMs(100)
				.maxDelayMs(200)
				.retryBudgetMs(5000)
				.build();

		BackgroundTask bg = new BackgroundTask();
		AtomicInteger attempts = new AtomicInteger(0);

		// Cancel after first failure
		assertThrows(IOException.class, () ->
			policy.execute(() -> {
				int n = attempts.incrementAndGet();
				if (n == 1) {
					bg.cancel(); // cancel after first attempt fails
				}
				throw new IOException("fail");
			}, bg)
		);
		assertEquals(1, attempts.get(), "Should stop after first attempt when cancelled between retries");
	}

	@Test
	void disabledPolicyNoRetries() {
		RetryPolicy policy = RetryPolicy.disabled();

		AtomicInteger attempts = new AtomicInteger(0);
		assertThrows(IOException.class, () ->
			policy.execute(() -> {
				attempts.incrementAndGet();
				throw new IOException("fail");
			}, null)
		);
		assertEquals(1, attempts.get(), "Disabled policy should not retry");
	}

	@Test
	void voidVariantWorks() throws Exception {
		RetryPolicy policy = RetryPolicy.defaults();
		AtomicInteger count = new AtomicInteger(0);
		policy.executeVoid(count::incrementAndGet, null);
		assertEquals(1, count.get());
	}

	@Test
	void retriesSocketTimeout() throws Exception {
		RetryPolicy policy = RetryPolicy.builder()
				.maxRetries(2)
				.initialDelayMs(100)
				.maxDelayMs(200)
				.retryBudgetMs(5000)
				.build();

		AtomicInteger attempts = new AtomicInteger(0);
		String result = policy.execute(() -> {
			if (attempts.incrementAndGet() == 1) {
				throw new SocketTimeoutException("Read timed out");
			}
			return "ok";
		}, null);

		assertEquals("ok", result);
		assertEquals(2, attempts.get());
	}

	@Test
	void isRetryableLogic() {
		assertTrue(RetryPolicy.isRetryable(new IOException("io")));
		assertTrue(RetryPolicy.isRetryable(new ConnectException("refused")));
		assertTrue(RetryPolicy.isRetryable(new SocketTimeoutException("timeout")));
		assertTrue(RetryPolicy.isRetryable(new DeepVioletException("wrap", new IOException("io"))));

		assertFalse(RetryPolicy.isRetryable(new TlsException("tls")));
		assertFalse(RetryPolicy.isRetryable(new RuntimeException("rt")));
		assertFalse(RetryPolicy.isRetryable(new IllegalArgumentException("arg")));
		assertFalse(RetryPolicy.isRetryable(new DeepVioletException("no io cause")));
	}

	@Test
	void builderValidation() {
		assertThrows(IllegalArgumentException.class, () ->
			RetryPolicy.builder().maxRetries(-1));
		assertThrows(IllegalArgumentException.class, () ->
			RetryPolicy.builder().initialDelayMs(50));
		assertThrows(IllegalArgumentException.class, () ->
			RetryPolicy.builder().retryBudgetMs(500));
		assertThrows(IllegalArgumentException.class, () ->
			RetryPolicy.builder().initialDelayMs(1000).maxDelayMs(500).build());
	}

	@Test
	void defaultsFactoryValues() {
		RetryPolicy p = RetryPolicy.defaults();
		assertEquals(3, p.getMaxRetries());
		assertEquals(500, p.getInitialDelayMs());
		assertEquals(4000, p.getMaxDelayMs());
		assertEquals(15000, p.getRetryBudgetMs());
	}
}
