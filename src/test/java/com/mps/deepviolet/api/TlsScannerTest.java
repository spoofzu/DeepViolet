package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

/**
 * Tests for {@link TlsScanner}. Unit tests run without network;
 * integration tests are {@code @Disabled}.
 */
public class TlsScannerTest {

	// ---- Unit tests (no network) ----

	@Test
	public void testEmptyTargetsReturnsEmptyResults() throws DeepVioletException {
		List<IScanResult> results = TlsScanner.scan(Collections.emptyList());
		assertTrue(results.isEmpty());
	}

	@Test
	public void testNullTargetsReturnsEmptyResults() throws DeepVioletException {
		List<IScanResult> results = TlsScanner.scan((java.util.Collection<String>) null);
		assertTrue(results.isEmpty());
	}

	@Test
	public void testConfigBuilderDefaults() {
		ScanConfig config = ScanConfig.defaults();
		assertEquals(10, config.getThreadCount());
		assertEquals(200, config.getSectionDelayMs());
		assertEquals(60000, config.getPerHostTimeoutMs());
		assertEquals(ISession.CIPHER_NAME_CONVENTION.IANA, config.getCipherNameConvention());
		assertNull(config.getEnabledProtocols());
		assertEquals(EnumSet.allOf(ScanSection.class), config.getEnabledSections());
	}

	@Test
	public void testConfigBuilderCustomValues() {
		ScanConfig config = ScanConfig.builder()
			.threadCount(5)
			.sectionDelayMs(500)
			.perHostTimeoutMs(30000)
			.cipherNameConvention(ISession.CIPHER_NAME_CONVENTION.OpenSSL)
			.enabledProtocols(Set.of(0x0303, 0x0304))
			.enabledSections(EnumSet.of(ScanSection.SESSION_INIT, ScanSection.CIPHER_ENUMERATION))
			.build();

		assertEquals(5, config.getThreadCount());
		assertEquals(500, config.getSectionDelayMs());
		assertEquals(30000, config.getPerHostTimeoutMs());
		assertEquals(ISession.CIPHER_NAME_CONVENTION.OpenSSL, config.getCipherNameConvention());
		assertEquals(Set.of(0x0303, 0x0304), config.getEnabledProtocols());
		assertEquals(EnumSet.of(ScanSection.SESSION_INIT, ScanSection.CIPHER_ENUMERATION),
			config.getEnabledSections());
	}

	@Test
	public void testConfigBuilderInvalidThreadCount() {
		assertThrows(IllegalArgumentException.class,
			() -> ScanConfig.builder().threadCount(0));
		assertThrows(IllegalArgumentException.class,
			() -> ScanConfig.builder().threadCount(-1));
	}

	@Test
	public void testConfigBuilderNegativeDelay() {
		assertThrows(IllegalArgumentException.class,
			() -> ScanConfig.builder().sectionDelayMs(-1));
	}

	@Test
	public void testConfigBuilderLowTimeout() {
		assertThrows(IllegalArgumentException.class,
			() -> ScanConfig.builder().perHostTimeoutMs(500));
	}

	@Test
	public void testConfigBuilderNullSections() {
		assertThrows(IllegalArgumentException.class,
			() -> ScanConfig.builder().enabledSections(null));
	}

	@Test
	public void testConfigBuilderEmptySections() {
		assertThrows(IllegalArgumentException.class,
			() -> ScanConfig.builder().enabledSections(EnumSet.noneOf(ScanSection.class)));
	}

	@Test
	public void testEnabledSectionsFiltering() {
		ScanConfig config = ScanConfig.builder()
			.enabledSections(EnumSet.of(ScanSection.SESSION_INIT))
			.build();
		assertTrue(config.getEnabledSections().contains(ScanSection.SESSION_INIT));
		assertFalse(config.getEnabledSections().contains(ScanSection.CIPHER_ENUMERATION));
		assertFalse(config.getEnabledSections().contains(ScanSection.RISK_SCORING));
	}

	@Test
	public void testScanSectionDisplayNames() {
		assertEquals("Session initialization", ScanSection.SESSION_INIT.getDisplayName());
		assertEquals("Cipher suite enumeration", ScanSection.CIPHER_ENUMERATION.getDisplayName());
		assertEquals("Certificate retrieval", ScanSection.CERTIFICATE_RETRIEVAL.getDisplayName());
		assertEquals("Risk scoring", ScanSection.RISK_SCORING.getDisplayName());
		assertEquals("TLS probe fingerprinting", ScanSection.TLS_FINGERPRINT.getDisplayName());
		assertEquals("DNS security check", ScanSection.DNS_SECURITY.getDisplayName());
		assertEquals("Revocation check", ScanSection.REVOCATION_CHECK.getDisplayName());
	}

	@Test
	public void testThreadStateValues() {
		assertEquals(3, ThreadState.values().length);
		assertNotNull(ThreadState.EXECUTING);
		assertNotNull(ThreadState.SLEEPING);
		assertNotNull(ThreadState.IDLE);
	}

	@Test
	public void testMonitorInitialState() {
		IScanMonitor monitor = TlsScanner.getMonitor();
		assertNotNull(monitor);
		assertEquals(0, monitor.getCompletedHostCount());
	}

	// ---- Integration tests (require network) ----

	@Disabled("Requires live network connection")
	@Test
	public void testMultiHostScanWithListener() throws DeepVioletException {
		List<String> targets = List.of("github.com", "google.com");

		AtomicInteger hostsStarted = new AtomicInteger(0);
		AtomicInteger hostsCompleted = new AtomicInteger(0);
		AtomicInteger sectionsStarted = new AtomicInteger(0);
		AtomicInteger sectionsCompleted = new AtomicInteger(0);
		List<IScanResult> scanResults = new ArrayList<>();

		IScanListener listener = new IScanListener() {
			@Override
			public void onHostStarted(URL url, int index, int total) {
				hostsStarted.incrementAndGet();
			}

			@Override
			public void onSectionStarted(URL url, ScanSection section) {
				sectionsStarted.incrementAndGet();
			}

			@Override
			public void onSectionCompleted(URL url, ScanSection section) {
				sectionsCompleted.incrementAndGet();
			}

			@Override
			public void onHostCompleted(IScanResult result, int completedCount, int total) {
				hostsCompleted.incrementAndGet();
			}

			@Override
			public void onScanCompleted(List<IScanResult> results) {
				scanResults.addAll(results);
			}
		};

		ScanConfig config = ScanConfig.builder()
			.threadCount(2)
			.sectionDelayMs(100)
			.enabledSections(EnumSet.of(ScanSection.SESSION_INIT, ScanSection.CIPHER_ENUMERATION))
			.build();

		List<IScanResult> results = TlsScanner.scan(targets, config, listener);

		assertEquals(2, results.size());
		assertEquals(2, hostsStarted.get());
		assertEquals(2, hostsCompleted.get());
		assertTrue(sectionsStarted.get() > 0);
	}

	@Disabled("Requires live network connection")
	@Test
	public void testFailingHostDoesNotAbortScan() throws DeepVioletException {
		List<String> targets = List.of("github.com", "this-host-does-not-exist.invalid");

		ScanConfig config = ScanConfig.builder()
			.threadCount(2)
			.sectionDelayMs(0)
			.perHostTimeoutMs(15000)
			.enabledSections(EnumSet.of(ScanSection.SESSION_INIT))
			.build();

		List<IScanResult> results = TlsScanner.scan(targets, config);

		assertEquals(2, results.size());
		// At least one should succeed (github.com)
		assertTrue(results.stream().anyMatch(IScanResult::isSuccess));
		// The invalid host should fail
		assertTrue(results.stream().anyMatch(r -> !r.isSuccess()));
	}

	@Disabled("Requires live network connection")
	@Test
	public void testResultOrderMatchesInput() throws DeepVioletException {
		List<String> targets = List.of("github.com", "google.com", "example.com");

		ScanConfig config = ScanConfig.builder()
			.threadCount(3)
			.sectionDelayMs(0)
			.enabledSections(EnumSet.of(ScanSection.SESSION_INIT))
			.build();

		List<IScanResult> results = TlsScanner.scan(targets, config);

		assertEquals(3, results.size());
		assertEquals("github.com", results.get(0).getURL().getHost());
		assertEquals("google.com", results.get(1).getURL().getHost());
		assertEquals("example.com", results.get(2).getURL().getHost());
	}

	@Disabled("Requires live network connection")
	@Test
	public void testMonitorThreadCountsDuringScan() throws Exception {
		List<String> targets = List.of("github.com", "google.com");

		ScanConfig config = ScanConfig.builder()
			.threadCount(2)
			.sectionDelayMs(500)
			.enabledSections(EnumSet.of(
				ScanSection.SESSION_INIT,
				ScanSection.CIPHER_ENUMERATION
			))
			.build();

		IScanMonitor monitor = TlsScanner.getMonitor();

		CompletableFuture<List<IScanResult>> future =
			TlsScanner.scanAsync(targets, config, null);

		// Wait briefly for scan to start
		Thread.sleep(1000);

		// Monitor should show running
		assertTrue(monitor.isRunning());
		assertEquals(2, monitor.getTotalHostCount());

		// Wait for completion
		List<IScanResult> results = future.get();
		assertEquals(2, results.size());
	}

	@Disabled("Requires live network connection")
	@Test
	public void testSectionCallbacksFireInOrder() throws DeepVioletException {
		List<String> targets = List.of("github.com");

		List<ScanSection> sectionOrder = Collections.synchronizedList(new ArrayList<>());

		IScanListener listener = new IScanListener() {
			@Override
			public void onSectionStarted(URL url, ScanSection section) {
				sectionOrder.add(section);
			}
		};

		ScanConfig config = ScanConfig.builder()
			.threadCount(1)
			.sectionDelayMs(0)
			.build();

		TlsScanner.scan(targets, config, listener);

		// Sections should fire in defined order
		assertTrue(sectionOrder.size() >= 2);
		assertEquals(ScanSection.SESSION_INIT, sectionOrder.get(0));
		assertEquals(ScanSection.CIPHER_ENUMERATION, sectionOrder.get(1));
	}
}
