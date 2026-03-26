package com.mps.deepviolet.api;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * TLS scanner with configurable threading, per-host rate limiting,
 * per-host results, and a global monitor for UI integration.
 *
 * <p>Uses a cached thread pool with a semaphore to cap concurrency.</p>
 *
 * @author Milton Smith
 */
public final class TlsScanner {

	private static final Logger logger = LoggerFactory.getLogger("com.mps.deepviolet.api.TlsScanner");

	private static final ScanMonitor monitor = new ScanMonitor();

	private TlsScanner() {}

	/**
	 * Scan with target spec strings using default configuration.
	 *
	 * @param targets target specification strings (hostname, IP, CIDR, ranges)
	 * @return per-host results
	 * @throws DeepVioletException on parsing or scan errors
	 */
	public static List<IScanResult> scan(Collection<String> targets) throws DeepVioletException {
		return scan(targets, ScanConfig.defaults(), null);
	}

	/**
	 * Scan with target spec strings and custom configuration.
	 *
	 * @param targets target specification strings
	 * @param config scan configuration
	 * @return per-host results
	 * @throws DeepVioletException on parsing or scan errors
	 */
	public static List<IScanResult> scan(Collection<String> targets, ScanConfig config) throws DeepVioletException {
		return scan(targets, config, null);
	}

	/**
	 * Scan with target spec strings, custom configuration, and a listener.
	 *
	 * @param targets target specification strings
	 * @param config scan configuration
	 * @param listener event listener, or null
	 * @return per-host results
	 * @throws DeepVioletException on parsing or scan errors
	 */
	public static List<IScanResult> scan(Collection<String> targets, ScanConfig config,
											IScanListener listener) throws DeepVioletException {
		if (targets == null || targets.isEmpty()) {
			return Collections.emptyList();
		}
		List<URL> urls = TargetSpec.parseAll(targets);
		return scan(urls, config, listener);
	}

	/**
	 * Scan with pre-parsed URLs.
	 *
	 * @param urls list of target URLs
	 * @param config scan configuration
	 * @param listener event listener, or null
	 * @return per-host results in the same order as the input
	 * @throws DeepVioletException on scan errors
	 */
	public static List<IScanResult> scan(List<URL> urls, ScanConfig config,
											IScanListener listener) throws DeepVioletException {
		if (urls == null || urls.isEmpty()) {
			return Collections.emptyList();
		}
		if (config == null) {
			config = ScanConfig.defaults();
		}

		final IScanListener safeListener = (listener != null) ? listener : new IScanListener() {};
		final int total = urls.size();
		final AtomicInteger completedCount = new AtomicInteger(0);

		monitor.reset();
		monitor.setTotalHostCount(total);
		monitor.setRunning(true);

		Semaphore semaphore = new Semaphore(config.getThreadCount());
		ScanConfig finalConfig = config;

		// Results array preserving input order
		@SuppressWarnings("unchecked")
		Future<ScanResult>[] futures = new Future[total];

		ExecutorService executor = Executors.newCachedThreadPool();
		try {
			for (int i = 0; i < total; i++) {
				final int index = i;
				final URL url = urls.get(i);

				futures[i] = executor.submit(() -> {
					semaphore.acquire();
					String threadName = Thread.currentThread().getName();
					ThreadStatus threadStatus = monitor.getOrCreateThread(threadName);
					try {
						threadStatus.setCurrentHost(url);
						threadStatus.setState(ThreadState.EXECUTING);

						safeListener.onHostStarted(url, index, total);

						ScanResult result = scanSingleHost(url, finalConfig, safeListener, threadStatus);

						int done = completedCount.incrementAndGet();
						monitor.incrementCompleted();
						safeListener.onHostCompleted(result, done, total);

						return result;
					} finally {
						threadStatus.setIdle();
						semaphore.release();
					}
				});
			}

			// Collect results in order
			List<IScanResult> results = new ArrayList<>(total);
			for (int i = 0; i < total; i++) {
				try {
					results.add(futures[i].get(finalConfig.getPerHostTimeoutMs() + 5000, TimeUnit.MILLISECONDS));
				} catch (TimeoutException e) {
					ScanResult timedOut = new ScanResult(urls.get(i));
					timedOut.setStartTime(Instant.now());
					timedOut.setEndTime(Instant.now());
					timedOut.setError(new DeepVioletException("Host scan timed out: " + urls.get(i)));
					results.add(timedOut);
				} catch (Exception e) {
					ScanResult failed = new ScanResult(urls.get(i));
					failed.setStartTime(Instant.now());
					failed.setEndTime(Instant.now());
					failed.setError(new DeepVioletException("Host scan failed: " + e.getMessage(), e));
					results.add(failed);
				}
			}

			safeListener.onScanCompleted(results);
			return results;

		} finally {
			executor.shutdownNow();
			monitor.setRunning(false);
		}
	}

	/**
	 * Async variant returning CompletableFuture.
	 *
	 * @param targets target specification strings
	 * @param config scan configuration
	 * @param listener event listener, or null
	 * @return future that completes with per-host results
	 * @throws DeepVioletException on target parsing errors
	 */
	public static CompletableFuture<List<IScanResult>> scanAsync(
			Collection<String> targets, ScanConfig config,
			IScanListener listener) throws DeepVioletException {
		// Parse targets eagerly so errors are thrown immediately
		if (targets == null || targets.isEmpty()) {
			return CompletableFuture.completedFuture(Collections.emptyList());
		}
		List<URL> urls = TargetSpec.parseAll(targets);
		ScanConfig finalConfig = (config != null) ? config : ScanConfig.defaults();

		return CompletableFuture.supplyAsync(() -> {
			try {
				return scan(urls, finalConfig, listener);
			} catch (DeepVioletException e) {
				throw new RuntimeException(e);
			}
		});
	}

	/**
	 * Get the monitor for polling thread/progress status during an active scan.
	 *
	 * @return the global scan monitor
	 */
	public static IScanMonitor getMonitor() {
		return monitor;
	}

	/**
	 * Scan a single host through all enabled sections.
	 * Sections are retried per the config's retry policy. RISK_SCORING
	 * runs last so it has full knowledge of which sections failed.
	 */
	private static ScanResult scanSingleHost(URL url, ScanConfig config,
												IScanListener listener,
												ThreadStatus threadStatus) {
		ScanResult result = new ScanResult(url);
		result.setStartTime(Instant.now());

		ISession session = null;
		IEngine eng = null;
		RetryPolicy retryPolicy = config.toRetryPolicy();

		// Create a BackgroundTask that bridges to the listener
		BackgroundTask bridgeTask = new BackgroundTask() {
			@Override
			public synchronized void setStatusBarMessage(String status) {
				super.setStatusBarMessage(status);
				threadStatus.setStatusMessage(status);
				listener.onHostStatus(url, status);
			}
		};

		try {
			// 1. SESSION_INIT (critical — re-throws on failure)
			if (config.getEnabledSections().contains(ScanSection.SESSION_INIT)) {
				executeSection(threadStatus, ScanSection.SESSION_INIT, listener, url);
				session = retryCriticalSection(retryPolicy, bridgeTask, () ->
						DeepVioletFactory.initializeSession(url));
				result.setSession(session);
				result.addCompletedSection(ScanSection.SESSION_INIT);
				sectionDelay(config, threadStatus);
			}

			// 2. CIPHER_ENUMERATION (critical — re-throws on failure)
			if (session != null && config.getEnabledSections().contains(ScanSection.CIPHER_ENUMERATION)) {
				executeSection(threadStatus, ScanSection.CIPHER_ENUMERATION, listener, url);
				final ISession sessionRef = session;
				eng = retryCriticalSection(retryPolicy, bridgeTask, () ->
						DeepVioletFactory.getEngine(sessionRef, config.getCipherNameConvention(),
								bridgeTask, config.getEnabledProtocols()));
				result.setEngine(eng);
				result.addCompletedSection(ScanSection.CIPHER_ENUMERATION);
				sectionDelay(config, threadStatus);
			}

			// 3. CERTIFICATE_RETRIEVAL
			if (eng != null && config.getEnabledSections().contains(ScanSection.CERTIFICATE_RETRIEVAL)) {
				executeSection(threadStatus, ScanSection.CERTIFICATE_RETRIEVAL, listener, url);
				if (retrySection(retryPolicy, bridgeTask, ScanSection.CERTIFICATE_RETRIEVAL,
						url, result, listener, eng::getCertificate)) {
					result.addCompletedSection(ScanSection.CERTIFICATE_RETRIEVAL);
				}
				sectionDelay(config, threadStatus);
			}

			// 4. TLS_FINGERPRINT
			if (eng != null && config.getEnabledSections().contains(ScanSection.TLS_FINGERPRINT)) {
				executeSection(threadStatus, ScanSection.TLS_FINGERPRINT, listener, url);
				if (retrySection(retryPolicy, bridgeTask, ScanSection.TLS_FINGERPRINT,
						url, result, listener, eng::getTlsFingerprint)) {
					result.addCompletedSection(ScanSection.TLS_FINGERPRINT);
				}
				sectionDelay(config, threadStatus);
			}

			// 5. DNS_SECURITY
			if (eng != null && config.getEnabledSections().contains(ScanSection.DNS_SECURITY)) {
				executeSection(threadStatus, ScanSection.DNS_SECURITY, listener, url);
				if (retrySection(retryPolicy, bridgeTask, ScanSection.DNS_SECURITY,
						url, result, listener, eng::getDnsStatus)) {
					result.addCompletedSection(ScanSection.DNS_SECURITY);
				}
				sectionDelay(config, threadStatus);
			}

			// 6. REVOCATION_CHECK
			if (eng != null && config.getEnabledSections().contains(ScanSection.REVOCATION_CHECK)) {
				executeSection(threadStatus, ScanSection.REVOCATION_CHECK, listener, url);
				if (retrySection(retryPolicy, bridgeTask, ScanSection.REVOCATION_CHECK,
						url, result, listener, () -> {
							X509Certificate cert = CipherSuiteUtil.getServerCertificate(url);
							X509Certificate[] chain = CipherSuiteUtil.getServerCertificateChain(url);
							X509Certificate issuer = (chain.length > 1) ? chain[1] : cert;
							RevocationChecker.check(cert, issuer);
						})) {
					result.addCompletedSection(ScanSection.REVOCATION_CHECK);
				}
				sectionDelay(config, threadStatus);
			}

			// 7. RISK_SCORING (last — uses failedSections for unevaluable deductions)
			if (eng != null && config.getEnabledSections().contains(ScanSection.RISK_SCORING)) {
				executeSection(threadStatus, ScanSection.RISK_SCORING, listener, url);
				try {
					eng.getRiskScore(result.getFailedSections());
					result.addCompletedSection(ScanSection.RISK_SCORING);
				} catch (DeepVioletException e) {
					logger.warn("Risk scoring failed for {}: {}", url, e.getMessage());
				}
			}

		} catch (DeepVioletException e) {
			result.setError(e);
			logger.error("Host scan failed for {}: {}", url, e.getMessage());
		} catch (Exception e) {
			result.setError(new DeepVioletException("Unexpected error scanning " + url, e));
			logger.error("Unexpected error scanning {}: {}", url, e.getMessage());
		}

		result.setEndTime(Instant.now());
		return result;
	}

	/**
	 * Retry a non-critical section. Returns true on success, false on failure.
	 * On failure, records the section as failed and fires the listener.
	 */
	private static boolean retrySection(RetryPolicy policy, BackgroundTask bg,
										ScanSection section, URL url,
										ScanResult result, IScanListener listener,
										RetryPolicy.RunnableWithException task) {
		try {
			policy.executeVoid(task, bg);
			return true;
		} catch (Exception e) {
			logger.warn("{} failed for {} after retries: {}", section.getDisplayName(), url, e.getMessage());
			result.addFailedSection(section);
			listener.onSectionFailed(url, section, policy.getMaxRetries() + 1, e);
			return false;
		}
	}

	/**
	 * Retry a critical section. Re-throws on failure (aborts host scan).
	 */
	private static <T> T retryCriticalSection(RetryPolicy policy, BackgroundTask bg,
											  java.util.concurrent.Callable<T> task) throws Exception {
		return policy.execute(task, bg);
	}

	private static void executeSection(ThreadStatus threadStatus, ScanSection section,
									   IScanListener listener, URL url) {
		threadStatus.setState(ThreadState.EXECUTING);
		threadStatus.setCurrentSection(section);
		threadStatus.setStatusMessage(section.getDisplayName());
		listener.onSectionStarted(url, section);
	}

	private static void sectionDelay(ScanConfig config, ThreadStatus threadStatus) {
		if (config.getSectionDelayMs() > 0) {
			threadStatus.setState(ThreadState.SLEEPING);
			threadStatus.setStatusMessage("Waiting between sections");
			try {
				Thread.sleep(config.getSectionDelayMs());
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
			}
		}
	}
}
