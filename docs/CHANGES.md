# Changes from Upstream

The upstream repository (github.com/spoofzu/DeepViolet) last received meaningful updates in **July 2019**. The local repository represents a major modernization effort.

**Upstream:** v5.1.16 / 5.1.17-SNAPSHOT, Java 8, Bouncy Castle dependency, basic TLS introspection, no TLS 1.3.
**Current:** 6.1.0 — Java 17+, Bouncy Castle removed, TLS 1.3 support, comprehensive TLS security analysis, AI-powered scan analysis (Anthropic/OpenAI/Ollama), scan persistence with envelope encryption (.dvscan files), post-quantum key exchange analysis, section-level retry with exponential backoff, failed-section-aware risk scoring, offline re-scoring. See [README](../README.md) for Maven coordinates.

---

## 6.1.0

### 20. Post-Quantum Key Exchange Analysis (new)
- Detect server support for ML-KEM hybrid and pure post-quantum key exchange groups
- New `NamedGroup` class with constants for all IANA TLS Named Groups including X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024, MLKEM768, MLKEM1024
- New `IEngine` methods: `getPqKeyExchangeSupported()`, `getPqKeyExchangeGroups()`, `getPqKeyExchangePreferred()`, `getPqPreferredGroup()`
- PQ preference detection via empty key_share ClientHello probe triggering HelloRetryRequest to reveal server's preferred group
- New `ClientHelloConfig.emptyKeyShare` flag for sending key_share with empty client_shares list

### 21. Section-Level Retry with Exponential Backoff (new)
- New `RetryPolicy` class with configurable exponential backoff and jitter for transient `IOException` failures
- Builder pattern: max retries, initial/max delays, and wall-clock budget
- Integrated with `ScanConfig` — new fields: `maxRetries`, `initialRetryDelayMs`, `maxRetryDelayMs`, `retryBudgetMs` (defaults: 3 retries, 500ms initial, 4s max, 15s budget)
- `ScanConfig.toRetryPolicy()` convenience method
- Non-critical sections (CERTIFICATE_RETRIEVAL, TLS_FINGERPRINT, DNS_SECURITY, REVOCATION_CHECK) retry and fail gracefully; critical sections (SESSION_INIT, CIPHER_ENUMERATION) retry and abort host scan on failure
- `BackgroundTask` cancellation respected during retry waits

### 22. Failed-Section-Aware Risk Scoring (new)
- New `IEngine.getRiskScore(Set<ScanSection>)` — compute risk score with knowledge of which scan sections failed after retries
- Failed sections produce `inconclusive` deductions instead of false positives
- 9 new scoring rules for failure-aware analysis: PQ key exchange (SYS-0001100), certificate retrieval failure (SYS-0001200), revocation check failure (SYS-0001300), DNS lookup failure (SYS-0001400), TLS fingerprint probe failure (SYS-0001500), weak PQ cipher (SYS-0021700), PQ not preferred (SYS-0030700), session PQ not supported (SYS-0050300), negotiated group PQ (SYS-0060700)
- New `IScanResult.getFailedSections()` — returns sections that failed after retries
- New `IScanListener.onSectionFailed(URL, ScanSection, int, Exception)` callback

### 23. Offline Re-Scoring (new)
- New `IEngine.buildRuleContext()` — capture all rule context properties for persistence
- New `IEngine.getRiskScore(RuleContext)` and `getRiskScore(RuleContext, InputStream)` — re-score a saved context without reconnecting to the server
- Rule context properties now include PQ key exchange fields: `session.pq_kex_supported`, `session.pq_kex_preferred`, `session.pq_kex_groups`, `session.pq_preferred_group`, `session.pq_kex_probe_failed`, `session.negotiated_group_pq`
- Scan failure properties: `scan.certificate_retrieval_failed`, `scan.revocation_check_failed`, `scan.dns_security_failed`, `scan.tls_fingerprint_failed`

### 24. Build & Infrastructure
- Version bumped to 6.1.0
- Removed deprecated `maven-javadoc-plugin` configuration from POM
- CI simplified to Java 21 only (removed Java 24 matrix build)
- Javadoc improvements across public API classes and interfaces

### 25. Java 17 Backport
- Minimum Java version lowered from 21 to 17 — zero public API changes
- Replaced virtual thread executor (`Executors.newVirtualThreadPerTaskExecutor()`) with cached thread pool in `TlsScanner`; semaphore still caps concurrency
- Replaced record pattern matching in switch with `instanceof` chain in `RuleExpressionEvaluator`
- Replaced `Thread.startVirtualThread()` with daemon thread in `PrintScan` sample
- CI and publish workflows updated to JDK 17

---

## 6.0.0

### Features

### 1. TLS 1.3 Support (new)
- Full TLS 1.3 protocol support — the upstream API predates widespread TLS 1.3 adoption and lacks any support for it
- Cipher suite enumeration for TLS 1.3 suites (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, etc.)
- TLS 1.3 handshake analysis including 0-RTT early data detection
- Protocol version negotiation testing across SSLv2 through TLS 1.3
- Protocol version filtering — callers can restrict which protocols are probed via `DeepVioletFactory.getEngine(..., Set<Integer> enabledProtocols)`

### 2. YAML-Based Risk Scoring Engine (new)
- **Externalized rule engine** with a custom expression DSL — 65 rules across 7 categories, all defined in `risk-scoring-rules.yaml`
- **Average-based scoring model (v3.0):** each rule has a normalized score (0.0–1.0); matched scores are averaged; result capped by a severity floor derived from the highest-scoring matched rule
- **7 scoring categories:** Protocols, Cipher Suites, Certificate, Revocation, Security Headers, DNS Security, Other
- Letter grades (A+ through F) mapped to risk levels (LOW / MEDIUM / HIGH / CRITICAL)
- **Expression DSL** with recursive descent parser:
  - Operators: `==`, `!=`, `<`, `>`, `<=`, `>=`, `and`, `or`, `not`, `contains`, `not contains`
  - Functions: `count()`, `count(list, field op value)`, `contains()`, `starts_with()`, `upper()`, `lower()`, `header()`, `header_present()`, `parse_max_age()`
  - Dot-notation property paths: `session.negotiated_protocol`, `cert.key_size`, etc.
- **Per-rule fields:** `id`, `description`, `enabled`, `score`, `when`, `when_inconclusive`, `inconclusive`
- **Inconclusive handling** — three mechanisms: `when_inconclusive` expression, `inconclusive: true` flag, and context-level warnings; inconclusive deductions are tracked but excluded from score averaging
- **Scoring diagnostics** with YAML source location tracking — when rule evaluation fails, diagnostics include the exact line:column from the YAML file
- **SYS-/USR- rule namespacing:** system rules use `SYS-NNNNNNN` IDs (immutable, compiled into the JAR); user rules use `USR-NNNNNNN` IDs (loaded from caller-supplied streams)
- **User rule loading:** `RulePolicyLoader.loadUserRules(InputStream)` validates USR- prefix, rejects SYS- prefix; `RulePolicy.mergeUserRules()` appends user rules to matching system categories or creates new ones
- **Three scoring entry points:** `getRiskScore()` (system rules only), `getRiskScore(String path)` (custom YAML file), `getRiskScore(InputStream)` (system + user rules merged)
- **Custom category support** — the scoring system supports user-defined categories beyond the built-in 7, addressable by string key
- New packages: `com.mps.deepviolet.api.scoring/` (1 class), `com.mps.deepviolet.api.scoring.rules/` (10 classes)

### 3. TLS Server Fingerprinting (new)
- JARM-inspired technique: 10 specially crafted ClientHello probes → 30-character fingerprint
- Characters 1–30: cipher+version response codes derived from server behavior
- Identifies server configuration patterns for grouping, change detection, and threat hunting
- New package: `com.mps.deepviolet.api.fingerprint/` (2 classes)

### 4. Enhanced Revocation & Certificate Transparency (new)
- Comprehensive checking: OCSP, CRL, OCSP Stapling, Must-Staple, OneCRL, CT/SCTs
- SCT extraction from 3 delivery methods: certificate extension, TLS extension, OCSP stapling
- Response timing, signature validation, and detailed status reporting
- New classes: `RevocationChecker`, `RevocationStatus`, `IRevocationStatus`

### 5. Raw TLS Metadata Extraction (new)
- Custom TLS socket implementation for direct handshake message parsing
- New package: `com.mps.deepviolet.api.tls/` (12 classes)
- Exposes ServerHello extensions (37 named TLS extension type constants + GREASE values), full certificate chain from TLS messages, OCSP stapled responses, handshake timing
- **ServerKeyExchange parsing** — extracts DHE prime size (bits) and ECDHE named curve (secp256r1, secp384r1, secp521r1, x25519, x448, etc.)
- **Fallback SCSV testing (RFC 7507)** — `TlsSocket.testFallbackScsv()` sends a downgraded ClientHello with the TLS_FALLBACK_SCSV sentinel cipher; returns true/false/null
- Convenience statics: `computeTlsFingerprint()`, `getCertificateChain()`, closeable pattern with try-with-resources

### 6. DNS Security Checking (new)
- JNDI-based DNS lookup for CAA (Certificate Authority Authorization) and DANE/TLSA records
- Uses `_<port>._tcp.<hostname>` naming convention for TLSA lookups with 5-second timeout
- Graceful failure — returns unavailable status on error
- Integrated into risk scoring as the DNS_SECURITY category (2 rules)
- New classes: `DnsSecurityChecker`, `DnsStatus`, `IDnsStatus`

### 7. HTTP Security Headers Analysis (new)
- HTTP response headers captured during session initialization
- 10 scoring rules covering: HSTS (missing, short max-age, missing includeSubDomains, missing preload), X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Permissions-Policy, Referrer-Policy, Cross-Origin-Opener-Policy
- Case-insensitive header lookup via `header()` and `header_present()` DSL functions
- Inconclusive handling when headers are unavailable (e.g., non-HTTP targets)

### 8. Cipher Map Migration & Custom Loading API (new)
- Cipher map migrated from JSON (`ciphermap.json`) to YAML (`ciphermap.yaml`) — 338 cipher suite entries with IANA, OpenSSL, GnuTLS, and NSS name mappings
- **Replaceable cipher map API** — callers can swap the entire cipher map at runtime:
  - `DeepVioletFactory.loadCipherMap(InputStream)` — parse-then-swap: validates new map before replacing internal state
  - `DeepVioletFactory.resetCipherMap()` — resets to built-in default; next use re-initializes from classpath
- Internal refactoring: parsing extracted into `CipherSuiteUtil.parseCipherMapYaml()` with atomic replacement

### 9. Bouncy Castle Removal
- Three new pure-Java replacements eliminate the Bouncy Castle dependency:
  - `X509Extensions.java` — X.509 extension parsing
  - `DerParser.java` — lightweight ASN.1 DER parser
  - `OcspClient.java` — pure Java OCSP client
- `ECCurveNames.java` — EC named curve OID-to-name mapping

### 10. TLS Scanning API (new)
- Scan multiple hosts concurrently with `TlsScanner` using a cached thread pool
- Rich target specification via `TargetSpec` — supports hostname, hostname:port, URL, IPv4, IPv4:port, **IPv6**, IPv6:port, IP ranges, CIDR, CIDR:port
- Builder-pattern `ScanConfig` for thread count, per-host section delay, timeout, protocol filtering, and section selection
- 7 scan sections (`ScanSection`): session init, cipher enumeration, certificate retrieval, risk scoring, TLS fingerprinting, DNS security, revocation check
- Per-host results (`IScanResult`) with section-level completion tracking
- Callback listener (`IScanListener`) for per-host/per-section events
- Pollable monitor (`IScanMonitor`) for UI Timer integration — thread states, completion counts
- Async variant via `TlsScanner.scanAsync()` returning `CompletableFuture`
- `DeepVioletFactory` made safe for concurrent use — `synchronized` removed from scan methods; double-checked locking on cipher map init; `TLS_CHAIN_TESTING_LOCK` for global SSL factory mutation

### 11. Cooperative Scan Cancellation & Pause (new)
- `BackgroundTask` extended with cooperative `cancel()` and `pause()` methods
- `isCancelled()` and `isPaused()` flags checked at natural scan boundaries — cipher enumeration loops, section transitions, handshake retries
- Cancel causes scan methods to bail out gracefully, returning partial results rather than throwing
- Pause halts progress until resumed; scan state is preserved
- Works for both single-host scans (via `DeepVioletFactory.getEngine(..., BackgroundTask)`) and multi-host scans (internal bridge task per host)
- Thread-safe: flags are `volatile` for cross-thread visibility

### 12. Sample Programs (new / expanded)
- 13 sample programs in `com.mps.deepviolet.samples/` (up from 2 in the old `com.mps.deepviolet.api.samples/`):

| Sample | Demonstrates |
|--------|-------------|
| `PrintCipherSuites` | IANA vs OpenSSL naming, grouping by protocol, strength evaluation |
| `PrintCertificateChain` | Full chain walk: DN, serial, version, signing algo, pubkey details, fingerprint, validity, trust, SANs |
| `PrintRevocationStatus` | OCSP, CRL, OneCRL, OCSP Stapling, Must-Staple, SCTs by source |
| `PrintSessionInfo` | DV version, host interfaces, connection properties, HTTP headers with security header highlighting |
| `PrintTlsFingerprint` | Fingerprint computation, parsing, summarization, per-probe iteration |
| `PrintBackgroundScan` | BackgroundTask subclass with protocol filtering (TLS 1.2 + TLS 1.3 only) |
| `PrintRiskScore` | Risk score with per-category breakdowns, deductions, severity, inconclusive markers |
| `PrintScan` | Scanning with ScanConfig builder, listener callbacks, monitor polling, IPv6 targets |
| `PrintAiAnalysis` | AI-powered TLS scan analysis (engine state, file, in-memory) with Anthropic/OpenAI/Ollama |
| `PrintAiChat` | Multi-turn AI chat about scan results |
| `PrintScanPersistence` | Save/load encrypted .dvscan files with envelope encryption (plain text, host locked, password locked) |
| `PrintSaveScan` | Scan hosts and save results to .dvscan files |
| `PrintScanDelta` | Compare two .dvscan files and display differences |

---

## Project Infrastructure

### 13. Dependency Modernization
- Java 8 → **Java 21+**
- JUnit 4 → **JUnit 5**; Mockito 3.0 → **5.14**
- Jackson 2.9 → **2.17**; Logback 1.2 → **1.5**
- Gson 2.13.1, SnakeYAML Engine 2.8 (new)

### 14. GitHub Actions CI/CD
- Travis CI removed → **GitHub Actions** (`.github/workflows/build.yml`)
- Matrix build: Java 21 + Java 24 (Temurin) with Maven cache
- Artifact upload: JAR per JDK version
- Triggers on push/PR to master/main + manual dispatch

### 15. Comprehensive Test Suite
- **24 test classes, 378 test methods** covering all subsystems:

| Area | Tests | Classes |
|------|-------|---------|
| Scoring rules engine | 185 | ExternalizedCategoryScorerTest (75), RuleExpressionEvaluatorTest (41), RuleExpressionParserTest (32), RulePolicyLoaderTest (32), RuleContextSerializationTest (5) |
| tls / raw TLS | 95 | ClientHelloTest (13), ServerHelloTest (16), TlsRecordLayerTest (13), ClientHelloConfigTest (16), TlsExtensionTest (9), TlsExceptionTest (9), ServerKeyExchangeTest (8), TlsSocketIntegrationTest (11) |
| Fingerprinting | 25 | TlsServerFingerprintTest (11), TlsBehaviorProbesTest (6), TlsServerFingerprintIntegrationTest (8) |
| Scoring integration | 8 | RiskScorerTest (8) |
| Cipher map | 12 | CipherMapTest (12) |
| Scanning | 39 | TargetSpecTest (21), TlsScannerTest (18) |
| Other | 14 | DeepVioletEngineMultiTest (8), DeepVioletEngineTest (3), FileUtilsTest (2), RiskScoreIntegrationTest (1) |

### 16. API Validation Tool (new)
- **`com.mps.deepviolet.validate`** package with standalone JAR (`mvn package -Pvalidate`)
- Compares DV API scan results against openssl field-by-field for any server
- 17 fields compared: subjectDN, issuerDN, serialNumber, version, signingAlgorithm, publicKeyAlgorithm, publicKeySize, publicKeyCurve, notValidBefore, notValidAfter, isSelfSigned, sanCount, fingerprint, negotiatedProtocol, negotiatedCipher, chainLength, ocspStapling
- `FieldNormalizer` handles cross-tool normalization: key algorithm mapping, ECDSA signing algorithm format, DN ordering, hex serial formatting, date format parsing, EC curve names, fingerprint formatting
- `OpensslRunner` executes openssl commands via ProcessBuilder with regex parsing compatible with LibreSSL and OpenSSL 3.x
- For bad-cert servers (expired, self-signed): DV session fails correctly, openssl shows why, result is PASS
- JSON and table output formats; exit code 0 on match, 1 on mismatch
- Also available via DeepVioletTools CLI: `dvcli.jar --validate <host>`

---

## Summary

| Category | # | Details |
|----------|---|---------|
| Protocol Support | 1 | TLS 1.3 full support with protocol filtering |
| Security Analysis | 5 | Risk scoring engine, fingerprinting, revocation/CT, DNS security, HTTP headers |
| TLS Internals | 1 | Raw metadata extraction (12 classes) with ServerKeyExchange parsing and Fallback SCSV |
| Scanning | 1 | Concurrent multi-host scanning with IPv6 support, virtual threads, configurable sections |
| Scan Control | 1 | Cooperative cancel and pause with cross-thread volatile flags |
| Customization | 2 | Replaceable cipher map, SYS-/USR- rule namespacing with user rule merging |
| Infrastructure | 3 | Bouncy Castle removal, dependency modernization, GitHub Actions CI |
| Validation | 1 | DV vs openssl field-by-field comparison tool with standalone JAR |
| Developer Experience | 2 | 13 sample programs, 378 tests across 24 test classes |

**Total: 17 significant improvements** transforming a dormant 2019-era scanning library into a modern, comprehensive TLS security analysis API.

---

### 18. AI Analysis Service (new — moved from DeepVioletTools)
- **`com.mps.deepviolet.api.ai`** package with `IAiAnalysisService`, `AiAnalysisService`, `AiConfig`, `AiProvider`, `AiChatMessage`, `AiAnalysisException`
- Supports Anthropic, OpenAI, and Ollama AI providers for TLS scan analysis and multi-turn chat
- `InputStream`-based `analyze()` decouples the API from data source (file, URL, in-memory)
- `AiConfig` builder replaces 7-8 parameter method signatures
- Integrated with `IEngine.getAiAnalysis(AiConfig)` for one-call analysis from engine state
- `DeepVioletFactory.getAiService()` factory entry point
- Two sample programs: `PrintAiAnalysis.java`, `PrintAiChat.java`

### 19. Scan Persistence with Three Save Modes (new — moved from DeepVioletTools)

Scan persistence is now an API-level feature. Any program using the DeepViolet API can save and load `.dvscan` files in the same format used by the DeepVioletTools GUI workbench. This enables workflows like running scans on remote servers or in CI/CD pipelines and transferring `.dvscan` files to a workstation for visual analysis.

- **`com.mps.deepviolet.persist`** package with `ScanFileIO`, `ScanFileMode`, `ScanSnapshot`, `HostSnapshot`, `SourceProvenance`, `ScanJsonCodec`
- **Three save modes** via `ScanFileMode` enum:
  - **Plain text** — unencrypted JSON, portable to any machine
  - **Host locked** — v2 envelope encryption with machine key only (zero-friction, default)
  - **Password locked** — v2 envelope encryption with password only (always requires password to open, portable across hosts)
- **v2 envelope encryption:** per-file DEK (AES-256-GCM), dual KEK slots (machine + password), HMAC-SHA256 slot integrity tag
- **Auto-detecting load:** `ScanFileIO.load()` transparently handles plain JSON, v1 encrypted, and v2 envelope encrypted files
- **`PasswordCallback`** functional interface for cross-machine password prompts (GUI shows dialog, CLI reads from env/file)
- **`com.mps.deepviolet.util.CryptoUtils`:** AES-256-GCM, DEK generation/wrapping, PBKDF2-HMAC-SHA256 password KDF, HMAC-SHA256, SHA-256, machine key management
- Immutable data holders: `ImmutableRiskScore`, `ImmutableCategoryScore`, `ImmutableDeduction`, `ImmutableCipherSuite`
- Sample program: `PrintScanPersistence.java` — demonstrates all three modes
