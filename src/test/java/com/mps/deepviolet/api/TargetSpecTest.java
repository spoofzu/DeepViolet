package com.mps.deepviolet.api;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URL;
import java.util.List;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link TargetSpec}. No network required.
 */
public class TargetSpecTest {

	@Test
	public void testParseHostname() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("github.com");
		assertEquals(1, urls.size());
		assertEquals("https", urls.get(0).getProtocol());
		assertEquals("github.com", urls.get(0).getHost());
		assertEquals(443, urls.get(0).getPort());
	}

	@Test
	public void testParseHostnameWithPort() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("github.com:8443");
		assertEquals(1, urls.size());
		assertEquals("github.com", urls.get(0).getHost());
		assertEquals(8443, urls.get(0).getPort());
	}

	@Test
	public void testParseUrl() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("https://github.com/");
		assertEquals(1, urls.size());
		assertEquals("https", urls.get(0).getProtocol());
		assertEquals("github.com", urls.get(0).getHost());
	}

	@Test
	public void testParseIpv4() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("192.168.1.1");
		assertEquals(1, urls.size());
		assertEquals("192.168.1.1", urls.get(0).getHost());
		assertEquals(443, urls.get(0).getPort());
	}

	@Test
	public void testParseIpv4WithPort() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("192.168.1.1:636");
		assertEquals(1, urls.size());
		assertEquals("192.168.1.1", urls.get(0).getHost());
		assertEquals(636, urls.get(0).getPort());
	}

	@Test
	public void testParseIpv6() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("[::1]");
		assertEquals(1, urls.size());
		assertEquals("[::1]", urls.get(0).getHost());
		assertEquals(443, urls.get(0).getPort());
	}

	@Test
	public void testParseIpv6WithPort() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("[::1]:8443");
		assertEquals(1, urls.size());
		assertEquals("[::1]", urls.get(0).getHost());
		assertEquals(8443, urls.get(0).getPort());
	}

	@Test
	public void testParseCidr24() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("10.0.0.0/24");
		assertEquals(254, urls.size());
		// First should be 10.0.0.1 (skips .0 network address)
		assertEquals("10.0.0.1", urls.get(0).getHost());
		// Last should be 10.0.0.254 (skips .255 broadcast)
		assertEquals("10.0.0.254", urls.get(253).getHost());
	}

	@Test
	public void testParseCidr32() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("10.0.0.5/32");
		assertEquals(1, urls.size());
		assertEquals("10.0.0.5", urls.get(0).getHost());
	}

	@Test
	public void testParseCidr24WithPort() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("10.0.0.0/24:636");
		assertEquals(254, urls.size());
		assertEquals(636, urls.get(0).getPort());
		assertEquals(636, urls.get(253).getPort());
	}

	@Test
	public void testParseIpRange() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("192.168.1.1-192.168.1.10");
		assertEquals(10, urls.size());
		assertEquals("192.168.1.1", urls.get(0).getHost());
		assertEquals("192.168.1.10", urls.get(9).getHost());
	}

	@Test
	public void testParseInvalidSpec() {
		assertThrows(DeepVioletException.class, () -> TargetSpec.parse(null));
		assertThrows(DeepVioletException.class, () -> TargetSpec.parse(""));
		assertThrows(DeepVioletException.class, () -> TargetSpec.parse("   "));
	}

	@Test
	public void testParseAllWithDuplicates() throws DeepVioletException {
		List<String> specs = List.of("github.com", "github.com", "google.com");
		List<URL> urls = TargetSpec.parseAll(specs);
		assertEquals(2, urls.size());
	}

	@Test
	public void testParseAllMixedFormats() throws DeepVioletException {
		List<String> specs = List.of("github.com", "192.168.1.1:636", "10.0.0.0/30");
		List<URL> urls = TargetSpec.parseAll(specs);
		// github.com (1) + 192.168.1.1:636 (1) + /30 = 2 hosts (.1 and .2)
		assertEquals(4, urls.size());
	}

	@Test
	public void testParseAllEmpty() throws DeepVioletException {
		assertEquals(0, TargetSpec.parseAll(List.of()).size());
	}

	@Test
	public void testParseAllNull() throws DeepVioletException {
		assertEquals(0, TargetSpec.parseAll(null).size());
	}

	@Test
	public void testParseDefaultPortOverride() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("github.com", 8080);
		assertEquals(1, urls.size());
		assertEquals(8080, urls.get(0).getPort());
	}

	@Test
	public void testParseExplicitPortOverridesDefault() throws DeepVioletException {
		List<URL> urls = TargetSpec.parse("github.com:9090", 8080);
		assertEquals(1, urls.size());
		assertEquals(9090, urls.get(0).getPort());
	}

	@Test
	public void testIpToLong() throws DeepVioletException {
		assertEquals(0x0A000001L, TargetSpec.ipToLong("10.0.0.1"));
		assertEquals(0xC0A80101L, TargetSpec.ipToLong("192.168.1.1"));
		assertEquals(0xFFFFFFFFL, TargetSpec.ipToLong("255.255.255.255"));
		assertEquals(0x00000000L, TargetSpec.ipToLong("0.0.0.0"));
	}

	@Test
	public void testLongToIp() {
		assertEquals("10.0.0.1", TargetSpec.longToIp(0x0A000001L));
		assertEquals("192.168.1.1", TargetSpec.longToIp(0xC0A80101L));
	}

	@Test
	public void testIpRangeReversed() {
		assertThrows(DeepVioletException.class,
			() -> TargetSpec.parse("192.168.1.10-192.168.1.1"));
	}
}
