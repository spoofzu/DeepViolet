package com.mps.deepviolet.samples;

import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.mps.deepviolet.api.DeepVioletFactory;
import com.mps.deepviolet.api.IEngine;
import com.mps.deepviolet.api.IHost;
import com.mps.deepviolet.api.ISession;
import com.mps.deepviolet.api.ISession.SESSION_PROPERTIES;

/**
 * Print DeepViolet version info, host interfaces, connection characteristics,
 * and HTTP response headers (with security header highlights).
 *
 * <p>Demonstrates: {@link IEngine} version methods, {@link ISession} properties,
 * {@link IHost} interface enumeration, and HTTP response header retrieval.</p>
 */
public class PrintSessionInfo {

	/** Security headers to highlight in the output. */
	private static final Set<String> SECURITY_HEADERS = Set.of(
			"strict-transport-security",
			"content-security-policy",
			"x-content-type-options",
			"x-frame-options",
			"x-xss-protection",
			"referrer-policy",
			"permissions-policy");

	public PrintSessionInfo() throws Exception {

		URL url = new URL("https://github.com/");
		ISession session = DeepVioletFactory.initializeSession(url);
		IEngine eng = DeepVioletFactory.getEngine(session);

		// --- DeepViolet version ---
		System.out.println("=== DeepViolet Version ===");
		System.out.println("Version:   " + eng.getDeepVioletStringVersion());
		System.out.println("Major:     " + eng.getDeepVioletMajorVersion());
		System.out.println("Minor:     " + eng.getDeepVioletMinorVersion());
		System.out.println("Build:     " + eng.getDeepVioletBuildVersion());
		System.out.println("Snapshot:  " + eng.isDeepVioletSnapShot());
		System.out.println();

		// --- Host interfaces ---
		System.out.println("=== Host Interfaces ===");
		IHost[] hosts = session.getHostInterfaces();
		for (IHost host : hosts) {
			System.out.println("Hostname:  " + host.getHostName());
			System.out.println("IP:        " + host.getHostIPAddress());
			System.out.println("Canonical: " + host.getHostCannonicalName());
			System.out.println("URL:       " + host.getURL());
			System.out.println();
		}

		// --- Connection characteristics ---
		System.out.println("=== Connection Characteristics ===");
		System.out.println("Session ID: " + session.getIdentity());
		for (SESSION_PROPERTIES key : SESSION_PROPERTIES.values()) {
			String value = session.getSessionPropertyValue(key);
			System.out.println(key + " = " + value);
		}
		System.out.println();

		// --- HTTP response headers ---
		System.out.println("=== HTTP Response Headers ===");
		Map<String, List<String>> headers = session.getHttpResponseHeaders();
		for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
			String name = entry.getKey();
			for (String value : entry.getValue()) {
				boolean isSecurity = name != null
						&& SECURITY_HEADERS.contains(name.toLowerCase());
				String marker = isSecurity ? " [SECURITY]" : "";
				System.out.println((name != null ? name : "<null>")
						+ ": " + value + marker);
			}
		}

		System.out.flush();
	}

	public static final void main(String[] args) {
		try {
			new PrintSessionInfo();
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}
}
