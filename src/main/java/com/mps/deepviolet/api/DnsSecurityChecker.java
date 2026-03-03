package com.mps.deepviolet.api;

import java.util.Hashtable;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks DNS security records (CAA and TLSA) for a given hostname.
 * Uses JNDI DNS provider for lookups with a 5-second timeout.
 */
class DnsSecurityChecker {

    private static final Logger logger = LoggerFactory.getLogger(DnsSecurityChecker.class);
    private static final int DNS_TIMEOUT_MS = 5000;

    /**
     * Check DNS security records for a hostname.
     * @param hostname Target hostname (e.g., "example.com")
     * @param port Target port (used for TLSA lookup)
     * @return DNS status with CAA and TLSA record presence
     */
    static DnsStatus check(String hostname, int port) {
        boolean hasCaa = false;
        boolean hasTlsa = false;
        boolean available = false;

        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("com.sun.jndi.dns.timeout.initial", String.valueOf(DNS_TIMEOUT_MS));
            env.put("com.sun.jndi.dns.timeout.retries", "1");

            DirContext ctx = new InitialDirContext(env);
            try {
                // CAA lookup
                hasCaa = hasRecords(ctx, hostname, "CAA");
                available = true;
            } catch (NamingException e) {
                logger.debug("CAA lookup failed for {}: {}", hostname, e.getMessage());
                // CAA may not be supported; try to continue
                available = true;
            }

            try {
                // TLSA lookup: _<port>._tcp.<hostname>
                String tlsaName = "_" + port + "._tcp." + hostname;
                hasTlsa = hasRecords(ctx, tlsaName, "TLSA");
            } catch (NamingException e) {
                logger.debug("TLSA lookup failed for {}: {}", hostname, e.getMessage());
                // TLSA failure is expected (most servers don't have TLSA)
            }

            ctx.close();
        } catch (NamingException e) {
            logger.debug("DNS security check failed for {}: {}", hostname, e.getMessage());
            return DnsStatus.unavailable();
        } catch (Exception e) {
            logger.warn("Unexpected error during DNS security check for {}: {}", hostname, e.getMessage());
            return DnsStatus.unavailable();
        }

        return new DnsStatus(available, hasCaa, hasTlsa);
    }

    private static boolean hasRecords(DirContext ctx, String name, String type) throws NamingException {
        try {
            Attributes attrs = ctx.getAttributes(name, new String[]{ type });
            if (attrs == null) return false;
            NamingEnumeration<? extends Attribute> all = attrs.getAll();
            boolean found = all.hasMore();
            all.close();
            return found;
        } catch (NamingException e) {
            // NXDOMAIN or no records = no records found
            String msg = e.getMessage();
            if (msg != null && (msg.contains("NXDOMAIN") || msg.contains("not found"))) {
                return false;
            }
            throw e;
        }
    }
}
