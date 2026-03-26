# Java 17 Backport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Backport DeepViolet from Java 21 to Java 17 so the library can run on JDK 17+ runtimes.

**Architecture:** The backport is surgical — only three Java 21-specific features are used in the codebase: virtual threads (2 locations), record pattern matching in switch (1 location), and try-with-resources on `ExecutorService` (which became `AutoCloseable` in Java 19). All other modern features (records, sealed interfaces, pattern matching for `instanceof`, switch expressions, text blocks) are Java 17-compatible and require no changes. Build config and CI workflows also need version bumps.

**Tech Stack:** Java 17, Maven, GitHub Actions

---

## Impact Analysis

| Feature | Java Version | Locations | Action |
|---|---|---|---|
| Virtual threads (`Thread.startVirtualThread`, `Executors.newVirtualThreadPerTaskExecutor`) | 21 | 2 files | Replace with platform threads / cached thread pool |
| Record pattern matching in switch (`case RecordType name ->`) | 21 | 1 file | Replace with if-else instanceof chain |
| `ExecutorService` as `AutoCloseable` (try-with-resources) | 19 | 1 file | Replace with manual shutdown in finally block |
| Records | 16 (standard in 17) | ~15 declarations | No change needed |
| Sealed interfaces | 17 | 1 file | No change needed |
| Pattern matching for `instanceof` | 16 (standard in 17) | ~31 uses | No change needed |
| Switch expressions | 14 (standard in 17) | ~48 uses | No change needed |
| Text blocks | 15 (standard in 17) | test files | No change needed |

## File Map

| File | Change |
|---|---|
| `pom.xml` | Change Java version properties from 21 to 17 |
| `.github/workflows/build.yml` | Change JDK version from 21 to 17 |
| `.github/workflows/publish.yml` | Change JDK version from 21 to 17 (2 locations) |
| `src/main/java/com/mps/deepviolet/api/TlsScanner.java` | Replace virtual thread executor + try-with-resources with cached thread pool + manual shutdown |
| `src/main/java/com/mps/deepviolet/api/scoring/rules/RuleExpressionEvaluator.java` | Replace record-pattern switch with if-else instanceof chain |
| `src/main/java/com/mps/deepviolet/samples/PrintScan.java` | Replace `Thread.startVirtualThread()` with `new Thread().start()` |

---

### Task 1: Update Build Configuration

**Files:**
- Modify: `pom.xml:41-42`

- [ ] **Step 1: Change Java version properties**

In `pom.xml`, change lines 41-42 from:

```xml
<java.target.version>21</java.target.version>
<java.source.version>21</java.source.version>
```

to:

```xml
<java.target.version>17</java.target.version>
<java.source.version>17</java.source.version>
```

These properties feed into `maven-compiler-plugin`'s `<source>`, `<target>`, and `<release>` settings (lines 91-93), so no other POM changes are needed.

- [ ] **Step 2: Verify dependencies are Java 17-compatible**

All current dependencies support Java 17:
- Gson 2.13.1 — requires Java 8+
- SnakeYAML Engine 2.8 — requires Java 11+
- JUnit Jupiter 5.10.3 — requires Java 8+
- Logback Classic 1.5.6 — requires Java 11+
- Mockito Core 5.14.2 — requires Java 11+

No dependency changes needed.

- [ ] **Step 3: Commit**

```bash
git add pom.xml
git commit -m "build: lower Java target from 21 to 17"
```

---

### Task 2: Replace Record Pattern Matching in Switch

**Files:**
- Modify: `src/main/java/com/mps/deepviolet/api/scoring/rules/RuleExpressionEvaluator.java:41-53`
- Test: `mvn test -Dtest=RuleExpressionEvaluatorTest`

- [ ] **Step 1: Run existing tests to establish baseline**

```bash
mvn test -Dtest="*RuleExpression*"
```

Expected: All tests PASS. Note the test count for verification later.

- [ ] **Step 2: Replace the record-pattern switch in `evaluate()`**

The current code at lines 41-53 uses Java 21 record patterns in a switch expression:

```java
public Object evaluate(RuleExpression expr) {
    return switch (expr) {
        case RuleExpression.Literal lit -> lit.value();
        case RuleExpression.PropertyRef ref -> context.resolve(ref.path());
        case RuleExpression.And and -> evaluateBoolean(and.left()) && evaluateBoolean(and.right());
        case RuleExpression.Or or -> evaluateBoolean(or.left()) || evaluateBoolean(or.right());
        case RuleExpression.Not not -> !evaluateBoolean(not.operand());
        case RuleExpression.Comparison cmp -> evaluateComparison(cmp);
        case RuleExpression.Contains cnt -> evaluateContains(cnt);
        case RuleExpression.FunctionCall fn -> evaluateFunction(fn);
        case RuleExpression.CountFiltered cf -> evaluateCountFiltered(cf);
    };
}
```

Replace with an if-else chain using pattern matching for `instanceof` (Java 17-compatible):

```java
public Object evaluate(RuleExpression expr) {
    if (expr instanceof RuleExpression.Literal lit) {
        return lit.value();
    } else if (expr instanceof RuleExpression.PropertyRef ref) {
        return context.resolve(ref.path());
    } else if (expr instanceof RuleExpression.And and) {
        return evaluateBoolean(and.left()) && evaluateBoolean(and.right());
    } else if (expr instanceof RuleExpression.Or or) {
        return evaluateBoolean(or.left()) || evaluateBoolean(or.right());
    } else if (expr instanceof RuleExpression.Not not) {
        return !evaluateBoolean(not.operand());
    } else if (expr instanceof RuleExpression.Comparison cmp) {
        return evaluateComparison(cmp);
    } else if (expr instanceof RuleExpression.Contains cnt) {
        return evaluateContains(cnt);
    } else if (expr instanceof RuleExpression.FunctionCall fn) {
        return evaluateFunction(fn);
    } else if (expr instanceof RuleExpression.CountFiltered cf) {
        return evaluateCountFiltered(cf);
    }
    throw new IllegalArgumentException("Unknown expression type: " + expr.getClass().getName());
}
```

Note: The `throw` at the end is needed because the sealed interface's exhaustiveness is only checked by switch pattern matching (Java 21), not by if-else chains. The sealed interface itself is Java 17-compatible.

- [ ] **Step 3: Run tests to verify behavior is preserved**

```bash
mvn test -Dtest="*RuleExpression*"
```

Expected: Same test count, all PASS.

- [ ] **Step 4: Commit**

```bash
git add src/main/java/com/mps/deepviolet/api/scoring/rules/RuleExpressionEvaluator.java
git commit -m "refactor: replace record-pattern switch with instanceof chain for Java 17"
```

---

### Task 3: Replace Virtual Thread Executor in TlsScanner

**Files:**
- Modify: `src/main/java/com/mps/deepviolet/api/TlsScanner.java:26,112`
- Test: `mvn test -Dtest=TlsScannerTest`

Two Java 21 features are used here:
1. `Executors.newVirtualThreadPerTaskExecutor()` — Java 21 API
2. `try (ExecutorService executor = ...)` — `ExecutorService` only implements `AutoCloseable` since Java 19

- [ ] **Step 1: Run existing tests to establish baseline**

```bash
mvn test -Dtest="*TlsScanner*"
```

Expected: All tests PASS.

- [ ] **Step 2: Update the Javadoc comment**

Change line 26 from:

```java
 * <p>Uses Java 21 virtual threads with a semaphore to cap concurrency.</p>
```

to:

```java
 * <p>Uses a cached thread pool with a semaphore to cap concurrency.</p>
```

- [ ] **Step 3: Replace virtual thread executor with cached thread pool and manual shutdown**

Replace the `scan(List<URL>, ScanConfig, IScanListener)` method's executor block. The current code at line 112:

```java
try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
```

Replace the entire try-with-resources block (lines 112-166) with a traditional try/finally pattern:

```java
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
```

Key differences from the original:
- `Executors.newCachedThreadPool()` instead of `newVirtualThreadPerTaskExecutor()` — creates platform threads on demand, reuses idle ones. The semaphore already caps concurrency to `config.getThreadCount()`.
- No try-with-resources on the executor — manual `shutdownNow()` in the finally block.
- The body of the `for` loop and result collection is identical to the original.

- [ ] **Step 4: Run tests to verify behavior is preserved**

```bash
mvn test -Dtest="*TlsScanner*"
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add src/main/java/com/mps/deepviolet/api/TlsScanner.java
git commit -m "refactor: replace virtual thread executor with cached thread pool for Java 17"
```

---

### Task 4: Replace Virtual Thread in PrintScan Sample

**Files:**
- Modify: `src/main/java/com/mps/deepviolet/samples/PrintScan.java:88`

- [ ] **Step 1: Replace `Thread.startVirtualThread()` with a standard thread**

Change line 88 from:

```java
Thread monitorThread = Thread.startVirtualThread(() -> {
```

to:

```java
Thread monitorThread = new Thread(() -> {
```

And add `.start()` after the lambda closes. The full replacement for lines 88-98:

```java
Thread monitorThread = new Thread(() -> {
    while (monitor.isRunning() || monitor.getCompletedHostCount() == 0) {
        System.out.printf("  [monitor] active=%d sleeping=%d idle=%d completed=%d/%d%n",
            monitor.getActiveThreadCount(),
            monitor.getSleepingThreadCount(),
            monitor.getIdleThreadCount(),
            monitor.getCompletedHostCount(),
            monitor.getTotalHostCount());
        try { Thread.sleep(500); } catch (InterruptedException e) { break; }
    }
});
monitorThread.setDaemon(true);
monitorThread.start();
```

Note: `setDaemon(true)` ensures the monitor thread doesn't prevent JVM shutdown, matching the virtual thread behavior (virtual threads are always daemon threads).

- [ ] **Step 2: Compile to verify**

```bash
mvn compile
```

Expected: BUILD SUCCESS

- [ ] **Step 3: Commit**

```bash
git add src/main/java/com/mps/deepviolet/samples/PrintScan.java
git commit -m "refactor: replace virtual thread with daemon thread in PrintScan sample for Java 17"
```

---

### Task 5: Update CI/CD Workflows

**Files:**
- Modify: `.github/workflows/build.yml:21`
- Modify: `.github/workflows/publish.yml:28,71`

- [ ] **Step 1: Update build.yml**

Change line 21 from:

```yaml
          java-version: '21'
```

to:

```yaml
          java-version: '17'
```

- [ ] **Step 2: Update publish.yml (build job)**

Change line 28 from:

```yaml
          java-version: 21
```

to:

```yaml
          java-version: 17
```

- [ ] **Step 3: Update publish.yml (publish job)**

Change line 71 from:

```yaml
          java-version: 21
```

to:

```yaml
          java-version: 17
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/build.yml .github/workflows/publish.yml
git commit -m "ci: update GitHub Actions workflows from JDK 21 to JDK 17"
```

---

### Task 6: Full Build Verification

- [ ] **Step 1: Run full build with tests**

```bash
mvn clean verify
```

Expected: BUILD SUCCESS with all tests passing.

- [ ] **Step 2: Verify the validate profile still builds**

```bash
mvn package -Pvalidate -DskipTests
```

Expected: BUILD SUCCESS, produces `target/DeepViolet-*-validate.jar`.

- [ ] **Step 3: Final commit (if any adjustments were needed)**

If any compilation errors or test failures were found and fixed in this step, commit those fixes.

```bash
git add -u
git commit -m "fix: resolve remaining Java 17 compatibility issues"
```

---

## Risk Assessment

**Low risk.** The backport touches only 4 source files with mechanical transformations. The behavioral semantics are preserved:

- **Thread pool choice:** `Executors.newCachedThreadPool()` with a semaphore provides the same concurrency model as virtual threads with a semaphore. The semaphore is the actual concurrency limiter; the thread pool just provides the threads. For I/O-bound TLS scanning, a cached pool is appropriate.
- **Record pattern switch → if-else:** Functionally identical. The sealed interface ensures no new subtypes can be added without updating the evaluator.
- **Daemon thread:** Matches virtual thread daemon behavior.
- **Dependencies:** All dependencies already support Java 11+, well within Java 17.
