package com.mps.deepviolet.api;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Parses host specification strings into scan target URLs.
 *
 * <p>Supported formats:</p>
 * <ul>
 *   <li>Hostname: {@code github.com} &rarr; {@code https://github.com:443}</li>
 *   <li>Hostname + port: {@code github.com:8443} &rarr; {@code https://github.com:8443}</li>
 *   <li>URL: {@code https://github.com/} &rarr; as-is</li>
 *   <li>IPv4: {@code 192.168.1.1} &rarr; {@code https://192.168.1.1:443}</li>
 *   <li>IPv4 + port: {@code 192.168.1.1:636} &rarr; {@code https://192.168.1.1:636}</li>
 *   <li>IPv6: {@code [::1]} &rarr; {@code https://[::1]:443}</li>
 *   <li>IPv6 + port: {@code [::1]:8443} &rarr; {@code https://[::1]:8443}</li>
 *   <li>IP range: {@code 192.168.1.1-192.168.1.10} &rarr; 10 targets</li>
 *   <li>CIDR: {@code 10.0.0.0/24} &rarr; 254 targets (.1-.254)</li>
 *   <li>CIDR + port: {@code 10.0.0.0/24:636} &rarr; 254 targets on port 636</li>
 * </ul>
 *
 * @author Milton Smith
 */
public final class TargetSpec {

	private static final int DEFAULT_PORT = 443;

	private TargetSpec() {}

	/**
	 * Parse a single target spec string into URLs using the default port (443).
	 *
	 * @param spec target specification string
	 * @return list of parsed URLs
	 * @throws DeepVioletException on invalid spec
	 */
	public static List<URL> parse(String spec) throws DeepVioletException {
		return parse(spec, DEFAULT_PORT);
	}

	/**
	 * Parse a single target spec string into URLs with a default port override.
	 *
	 * @param spec target specification string
	 * @param defaultPort default port when none is specified
	 * @return list of parsed URLs
	 * @throws DeepVioletException on invalid spec
	 */
	public static List<URL> parse(String spec, int defaultPort) throws DeepVioletException {
		if (spec == null || spec.trim().isEmpty()) {
			throw new DeepVioletException("Target spec must not be null or empty");
		}
		spec = spec.trim();

		try {
			// URL format
			if (spec.startsWith("https://") || spec.startsWith("http://")) {
				return List.of(new URL(spec));
			}

			// CIDR format: 10.0.0.0/24 or 10.0.0.0/24:636
			if (spec.contains("/") && !spec.startsWith("[")) {
				return parseCidr(spec, defaultPort);
			}

			// IP range format: 192.168.1.1-192.168.1.10
			if (spec.contains("-") && !spec.startsWith("[") && isIpRange(spec)) {
				return parseIpRange(spec, defaultPort);
			}

			// IPv6 format: [::1] or [::1]:8443
			if (spec.startsWith("[")) {
				return List.of(parseIpv6(spec, defaultPort));
			}

			// Hostname or IPv4 with optional port: github.com or github.com:8443
			return List.of(parseHostPort(spec, defaultPort));

		} catch (DeepVioletException e) {
			throw e;
		} catch (Exception e) {
			throw new DeepVioletException("Invalid target spec: " + spec, e);
		}
	}

	/**
	 * Parse multiple specs, expanding ranges/CIDRs, deduplicating.
	 *
	 * @param specs collection of target specification strings
	 * @return deduplicated list of URLs in insertion order
	 * @throws DeepVioletException on invalid spec
	 */
	public static List<URL> parseAll(Collection<String> specs) throws DeepVioletException {
		return parseAll(specs, DEFAULT_PORT);
	}

	/**
	 * Parse multiple specs with default port override.
	 *
	 * @param specs collection of target specification strings
	 * @param defaultPort default port when none is specified
	 * @return deduplicated list of URLs in insertion order
	 * @throws DeepVioletException on invalid spec
	 */
	public static List<URL> parseAll(Collection<String> specs, int defaultPort) throws DeepVioletException {
		if (specs == null || specs.isEmpty()) {
			return List.of();
		}
		Set<URL> seen = new LinkedHashSet<>();
		for (String spec : specs) {
			seen.addAll(parse(spec, defaultPort));
		}
		return new ArrayList<>(seen);
	}

	private static URL parseHostPort(String spec, int defaultPort) throws DeepVioletException {
		int port = defaultPort;
		String host = spec;

		// Check for port: hostname:port or ip:port
		int lastColon = spec.lastIndexOf(':');
		if (lastColon > 0) {
			String portStr = spec.substring(lastColon + 1);
			try {
				port = Integer.parseInt(portStr);
				host = spec.substring(0, lastColon);
			} catch (NumberFormatException e) {
				// Not a port, treat entire string as hostname
			}
		}

		return toUrl(host, port);
	}

	private static URL parseIpv6(String spec, int defaultPort) throws DeepVioletException {
		int closeBracket = spec.indexOf(']');
		if (closeBracket < 0) {
			throw new DeepVioletException("Invalid IPv6 spec (missing closing bracket): " + spec);
		}

		String host = spec.substring(0, closeBracket + 1);
		int port = defaultPort;

		if (closeBracket + 1 < spec.length()) {
			String rest = spec.substring(closeBracket + 1);
			if (rest.startsWith(":")) {
				try {
					port = Integer.parseInt(rest.substring(1));
				} catch (NumberFormatException e) {
					throw new DeepVioletException("Invalid port in IPv6 spec: " + spec, e);
				}
			}
		}

		return toUrl(host, port);
	}

	private static List<URL> parseCidr(String spec, int defaultPort) throws DeepVioletException {
		int port = defaultPort;
		String cidr = spec;

		// Check for port suffix: 10.0.0.0/24:636
		int slashIdx = spec.indexOf('/');
		String afterSlash = spec.substring(slashIdx + 1);
		int colonIdx = afterSlash.indexOf(':');
		if (colonIdx >= 0) {
			try {
				port = Integer.parseInt(afterSlash.substring(colonIdx + 1));
			} catch (NumberFormatException e) {
				throw new DeepVioletException("Invalid port in CIDR spec: " + spec, e);
			}
			cidr = spec.substring(0, slashIdx + 1 + colonIdx);
		}

		// Parse CIDR
		String[] parts = cidr.split("/");
		if (parts.length != 2) {
			throw new DeepVioletException("Invalid CIDR notation: " + spec);
		}

		long baseAddr = ipToLong(parts[0]);
		int prefixLen;
		try {
			prefixLen = Integer.parseInt(parts[1]);
		} catch (NumberFormatException e) {
			throw new DeepVioletException("Invalid CIDR prefix length: " + spec, e);
		}

		if (prefixLen < 0 || prefixLen > 32) {
			throw new DeepVioletException("CIDR prefix length must be 0-32: " + spec);
		}

		// /32 = single host
		if (prefixLen == 32) {
			return List.of(toUrl(parts[0], port));
		}

		long mask = 0xFFFFFFFFL << (32 - prefixLen);
		long network = baseAddr & mask;
		long hostCount = 1L << (32 - prefixLen);

		List<URL> urls = new ArrayList<>();
		// Skip network address (.0) and broadcast address (.255 for /24)
		for (long i = 1; i < hostCount - 1; i++) {
			long addr = network + i;
			urls.add(toUrl(longToIp(addr), port));
		}

		return urls;
	}

	private static boolean isIpRange(String spec) {
		int dashIdx = spec.indexOf('-');
		if (dashIdx < 0) return false;
		String left = spec.substring(0, dashIdx);
		String right = spec.substring(dashIdx + 1);
		// Both sides should look like IPv4 addresses
		return isIpv4(left) && isIpv4(right);
	}

	private static List<URL> parseIpRange(String spec, int defaultPort) throws DeepVioletException {
		int dashIdx = spec.indexOf('-');
		String startIp = spec.substring(0, dashIdx);
		String endIp = spec.substring(dashIdx + 1);

		long start = ipToLong(startIp);
		long end = ipToLong(endIp);

		if (end < start) {
			throw new DeepVioletException("IP range end must be >= start: " + spec);
		}

		if (end - start > 65534) {
			throw new DeepVioletException("IP range too large (max 65534 hosts): " + spec);
		}

		List<URL> urls = new ArrayList<>();
		for (long addr = start; addr <= end; addr++) {
			urls.add(toUrl(longToIp(addr), defaultPort));
		}
		return urls;
	}

	private static boolean isIpv4(String s) {
		String[] octets = s.split("\\.");
		if (octets.length != 4) return false;
		for (String octet : octets) {
			try {
				int val = Integer.parseInt(octet);
				if (val < 0 || val > 255) return false;
			} catch (NumberFormatException e) {
				return false;
			}
		}
		return true;
	}

	static long ipToLong(String ip) throws DeepVioletException {
		String[] octets = ip.split("\\.");
		if (octets.length != 4) {
			throw new DeepVioletException("Invalid IPv4 address: " + ip);
		}
		long result = 0;
		for (int i = 0; i < 4; i++) {
			int octet;
			try {
				octet = Integer.parseInt(octets[i]);
			} catch (NumberFormatException e) {
				throw new DeepVioletException("Invalid octet in IPv4 address: " + ip, e);
			}
			if (octet < 0 || octet > 255) {
				throw new DeepVioletException("Octet out of range in IPv4 address: " + ip);
			}
			result = (result << 8) | octet;
		}
		return result;
	}

	static String longToIp(long addr) {
		return ((addr >> 24) & 0xFF) + "." +
				((addr >> 16) & 0xFF) + "." +
				((addr >> 8) & 0xFF) + "." +
				(addr & 0xFF);
	}

	private static URL toUrl(String host, int port) throws DeepVioletException {
		try {
			return new URL("https://" + host + ":" + port);
		} catch (MalformedURLException e) {
			throw new DeepVioletException("Cannot form URL for host=" + host + " port=" + port, e);
		}
	}
}
