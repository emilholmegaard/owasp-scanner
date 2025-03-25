package org.emilholmegaard.owaspscanner.core;

/**
 * Configuration class for scanner performance tuning.
 * Provides options to adjust how the scanner operates based on system capacity and requirements.
 */
public class ScannerConfig {
    private boolean parallelProcessing = true;
    private int maxThreads = Runtime.getRuntime().availableProcessors();
    private boolean cacheFileContent = true;
    private long maxLineLengthBytes = 5000;
    private boolean earlyTermination = true;
    private int maxViolationsPerFile = 100;
    private long maxFileSizeBytes = 10 * 1024 * 1024; // 10MB

    /**
     * Creates a new ScannerConfig with default settings.
     */
    public ScannerConfig() {
        // Default constructor with default field values
    }

    /**
     * Returns the default scanner configuration.
     * @return A new ScannerConfig instance with default settings
     */
    public static ScannerConfig defaultConfig() {
        return new ScannerConfig();
    }

    /**
     * Returns a configuration optimized for speed.
     * This configuration focuses on scanning quickly, potentially at the expense of thoroughness.
     * @return A new ScannerConfig instance with speed-optimized settings
     */
    public static ScannerConfig fastConfig() {
        return new ScannerConfig()
            .setParallelProcessing(true)
            .setMaxThreads(Runtime.getRuntime().availableProcessors() * 2)
            .setCacheFileContent(true)
            .setEarlyTermination(true)
            .setMaxViolationsPerFile(10);
    }

    /**
     * Returns a thorough scanner configuration.
     * This configuration focuses on completeness, potentially at the expense of speed.
     * @return A new ScannerConfig instance with thoroughness-optimized settings
     */
    public static ScannerConfig thoroughConfig() {
        return new ScannerConfig()
            .setParallelProcessing(true)
            .setCacheFileContent(true)
            .setEarlyTermination(false)
            .setMaxViolationsPerFile(Integer.MAX_VALUE);
    }

    /**
     * Returns whether parallel processing is enabled.
     * @return true if parallel processing is enabled, false otherwise
     */
    public boolean isParallelProcessing() {
        return parallelProcessing;
    }

    /**
     * Sets whether to use parallel processing during scanning.
     * @param parallelProcessing true to enable parallel processing, false to use sequential processing
     * @return this ScannerConfig instance for method chaining
     */
    public ScannerConfig setParallelProcessing(boolean parallelProcessing) {
        this.parallelProcessing = parallelProcessing;
        return this;
    }

    /**
     * Returns the maximum number of threads to use for parallel processing.
     * @return the maximum number of threads
     */
    public int getMaxThreads() {
        return maxThreads;
    }

    /**
     * Sets the maximum number of threads to use for parallel processing.
     * @param maxThreads the maximum number of threads
     * @return this ScannerConfig instance for method chaining
     */
    public ScannerConfig setMaxThreads(int maxThreads) {
        this.maxThreads = maxThreads > 0 ? maxThreads : Runtime.getRuntime().availableProcessors();
        return this;
    }

    /**
     * Returns whether file content caching is enabled.
     * @return true if file content caching is enabled, false otherwise
     */
    public boolean isCacheFileContent() {
        return cacheFileContent;
    }

    /**
     * Sets whether to cache file content during scanning.
     * @param cacheFileContent true to enable file content caching, false to disable
     * @return this ScannerConfig instance for method chaining
     */
    public ScannerConfig setCacheFileContent(boolean cacheFileContent) {
        this.cacheFileContent = cacheFileContent;
        return this;
    }

    /**
     * Returns the maximum line length in bytes before truncation.
     * @return the maximum line length in bytes
     */
    public long getMaxLineLengthBytes() {
        return maxLineLengthBytes;
    }

    /**
     * Sets the maximum line length in bytes before truncation.
     * @param maxLineLengthBytes the maximum line length in bytes
     * @return this ScannerConfig instance for method chaining
     */
    public ScannerConfig setMaxLineLengthBytes(long maxLineLengthBytes) {
        this.maxLineLengthBytes = maxLineLengthBytes > 0 ? maxLineLengthBytes : 5000;
        return this;
    }

    /**
     * Returns whether early termination is enabled.
     * @return true if early termination is enabled, false otherwise
     */
    public boolean isEarlyTermination() {
        return earlyTermination;
    }

    /**
     * Sets whether to terminate scanning a file early when a threshold of violations is reached.
     * @param earlyTermination true to enable early termination, false to scan the entire file
     * @return this ScannerConfig instance for method chaining
     */
    public ScannerConfig setEarlyTermination(boolean earlyTermination) {
        this.earlyTermination = earlyTermination;
        return this;
    }

    /**
     * Returns the maximum number of violations to collect per file before early termination.
     * @return the maximum violations per file
     */
    public int getMaxViolationsPerFile() {
        return maxViolationsPerFile;
    }

    /**
     * Sets the maximum number of violations to collect per file before early termination.
     * @param maxViolationsPerFile the maximum violations per file
     * @return this ScannerConfig instance for method chaining
     */
    public ScannerConfig setMaxViolationsPerFile(int maxViolationsPerFile) {
        this.maxViolationsPerFile = maxViolationsPerFile > 0 ? maxViolationsPerFile : 100;
        return this;
    }

    /**
     * Returns the maximum file size in bytes to process.
     * @return the maximum file size in bytes
     */
    public long getMaxFileSizeBytes() {
        return maxFileSizeBytes;
    }

    /**
     * Sets the maximum file size in bytes to process.
     * Files larger than this will be skipped.
     * @param maxFileSizeBytes the maximum file size in bytes
     * @return this ScannerConfig instance for method chaining
     */
    public ScannerConfig setMaxFileSizeBytes(long maxFileSizeBytes) {
        this.maxFileSizeBytes = maxFileSizeBytes > 0 ? maxFileSizeBytes : 10 * 1024 * 1024;
        return this;
    }
}
