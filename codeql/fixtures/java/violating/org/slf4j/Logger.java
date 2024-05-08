package org.slf4j;

/**
 * Minimal SLF4J shape for CodeQL fixture extraction.
 *
 * Fixtures are analysed with --build-mode=none. The JDK sinks in Pii.qll
 * (java.util.logging.Logger and java.io.PrintStream) resolve from the JDK, but
 * third-party sinks do not resolve unless their types are present in source.
 * This stub deliberately makes org.slf4j.Logger resolvable without pulling a
 * Maven dependency into the fixture harness.
 */
public interface Logger {
    void trace(String message, Object... args);
    void debug(String message, Object... args);
    void info(String message, Object... args);
    void warn(String message, Object... args);
    void error(String message, Object... args);
}