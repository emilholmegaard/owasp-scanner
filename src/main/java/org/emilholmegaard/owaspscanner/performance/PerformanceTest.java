package org.emilholmegaard.owaspscanner.performance;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Performance test utility for the OWASP Scanner.
 * This class implements a command-line tool that measures and records various
 * performance metrics
 * while running security scans on a directory of files.
 * 
 * <p>
 * Metrics collected include:
 * <ul>
 * <li>Execution time</li>
 * <li>Memory usage (peak and average)</li>
 * <li>File count</li>
 * <li>Number of security violations found</li>
 * <li>System information (CPU cores, max heap size)</li>
 * </ul>
 * 
 * <p>
 * Results are saved to a CSV file for further analysis.
 *
 * @author Emil Holmegaard
 * @version 1.0
 */
@Component
public class PerformanceTest implements CommandLineRunner {

    /** Runtime instance for memory measurements */
    private final Runtime runtime;

    /** Formatter for timestamp entries in the CSV output */
    private final DateTimeFormatter timestampFormatter;

    /** Scanner engine instance for performing security scans */
    private final BaseScannerEngine scannerEngine;

    /** List to store memory usage samples during test execution */
    private final List<Long> memorySamples;

    /** Counter for tracking number of files processed */
    private final AtomicInteger fileCounter;

    /** Peak memory usage during test execution */
    private long peakMemory;

    /** Initial memory usage before test execution */
    private long initialMemory;

    /** Test start timestamp */
    private Instant start;

    /** Test end timestamp */
    private Instant end;

    @Autowired
    public PerformanceTest(BaseScannerEngine scannerEngine) {
        this.runtime = Runtime.getRuntime();
        this.timestampFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
        this.scannerEngine = scannerEngine;
        this.memorySamples = new ArrayList<>();
        this.fileCounter = new AtomicInteger(0);
    }

    /**
     * Entry point for command-line execution. Processes arguments and initiates the
     * performance test.
     *
     * @param args Command line arguments:
     *             <ul>
     *             <li>args[0] - Directory path containing files to scan</li>
     *             <li>args[1] - Output CSV file path</li>
     *             <li>args[2] - (Optional) Test run label</li>
     *             </ul>
     */
    @Override
    public void run(String... args) {
        if (args.length < 2) {
            System.out.println("Usage: PerformanceTest <test_directory> <output_csv> [test_label]");
            System.out.println("  test_directory  - Directory containing test files to scan");
            System.out.println("  output_csv      - Path to CSV file to append results to");
            System.out.println(
                    "  test_label      - Optional label for this test run (e.g., 'baseline' or 'after-fix-123')");
            return;
        }

        String testDir = args[0];
        String outputFile = args[1];
        String testLabel = args.length > 2 ? args[2] : "unlabeled";

        try {
            runPerformanceTest(testDir, outputFile, testLabel);
        } catch (Exception e) {
            System.err.println("Error running performance test: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Executes a performance test by scanning the specified directory and recording
     * metrics.
     * Results are appended to the specified CSV file.
     *
     * @param testDirectory Directory containing files to scan
     * @param outputCsv     Path to CSV file where results should be written
     * @param testLabel     Label to identify this test run
     * @throws IOException          If there is an error reading test files or
     *                              writing results
     * @throws InterruptedException If the garbage collection pause is interrupted
     */
    public void runPerformanceTest(String testDirectory, String outputCsv, String testLabel)
            throws IOException, InterruptedException {
        Path directoryPath = Paths.get(testDirectory).normalize();
        File resultsFile = new File(outputCsv);
        boolean fileExists = resultsFile.exists();

        // Make sure parent directories exist
        if (resultsFile.getParentFile() != null) {
            resultsFile.getParentFile().mkdirs();
        }

        // Run GC to start with a clean state
        System.gc();
        Thread.sleep(200); // Short pause to let GC complete

        // Run the test and gather metrics
        PerformanceMetrics metrics = testScanPerformance(directoryPath);

        // Add the test label
        metrics.testLabel = testLabel;

        // Write results to CSV
        try (FileWriter writer = new FileWriter(resultsFile, true)) {
            // Write header if new file
            if (!fileExists) {
                writer.write("Timestamp,TestLabel,Directory,DurationMs,PeakMemoryMB,AvgMemoryMB," +
                        "FileCount,TotalViolations,CpuCores,MaxHeapMB\n");
            }

            // Write new row
            writer.write(String.format("%s,%s,%s,%d,%.2f,%.2f,%d,%d,%d,%d\n",
                    ZonedDateTime.now().format(timestampFormatter),
                    metrics.testLabel,
                    directoryPath.toString().replace(",", ";"), // Escape commas in path
                    metrics.durationMs,
                    metrics.peakMemoryMB,
                    metrics.avgMemoryMB,
                    metrics.fileCount,
                    metrics.violationCount,
                    metrics.cpuCores,
                    metrics.maxHeapMB));

            System.out.println("\nPerformance test results saved to: " + outputCsv);
        }

        // Print summary
        System.out.println("\nPerformance Test Summary:");
        System.out.println("-------------------------");
        System.out.println("Test label: " + metrics.testLabel);
        System.out.println("Test directory: " + directoryPath);
        System.out.println("Files scanned: " + metrics.fileCount);
        System.out.println("Violations found: " + metrics.violationCount);
        System.out.println("Total scan time: " + formatDuration(metrics.durationMs));
        System.out.println("Peak memory usage: " + String.format("%.2f MB", metrics.peakMemoryMB));
        System.out.println("Average memory usage: " + String.format("%.2f MB", metrics.avgMemoryMB));
        System.out.println("CPU cores: " + metrics.cpuCores);
        System.out.println("Max heap size: " + metrics.maxHeapMB + " MB");
        System.out.println("\nJVM version: " + System.getProperty("java.version"));
        System.out.println("OS: " + System.getProperty("os.name") + " " + System.getProperty("os.version"));
    }

    /**
     * Performs the actual security scan and collects performance metrics.
     *
     * @param directoryPath Directory to scan
     * @return PerformanceMetrics object containing collected metrics
     * @throws IOException          If there is an error reading files
     * @throws InterruptedException If the thread is interrupted during execution
     */
    private PerformanceMetrics testScanPerformance(Path directoryPath) throws IOException, InterruptedException {
        // Initialize metrics collection
        start = Instant.now();
        initialMemory = getUsedMemory();
        peakMemory = initialMemory;
        memorySamples.clear();
        fileCounter.set(0);

        // Run the scan
        List<SecurityViolation> violations = scannerEngine.scanDirectory(directoryPath);
        end = Instant.now();

        // Check peak memory one more time
        long currentMemory = getUsedMemory();
        if (currentMemory > peakMemory) {
            peakMemory = currentMemory;
        }

        // Calculate average memory usage
        double avgMemory = memorySamples.stream()
                .mapToLong(Long::longValue)
                .average()
                .orElse(0.0);

        // Create metrics
        PerformanceMetrics metrics = new PerformanceMetrics();
        metrics.durationMs = Duration.between(start, end).toMillis();
        metrics.peakMemoryMB = (peakMemory - initialMemory) / (1024.0 * 1024.0);
        metrics.avgMemoryMB = avgMemory / (1024.0 * 1024.0);
        metrics.fileCount = fileCounter.get();
        metrics.violationCount = violations.size();
        metrics.cpuCores = Runtime.getRuntime().availableProcessors();
        metrics.maxHeapMB = runtime.maxMemory() / (1024 * 1024);

        return metrics;
    }

    /**
     * Calculates the current memory usage of the JVM.
     *
     * @return Current used memory in bytes
     */
    private long getUsedMemory() {
        return runtime.totalMemory() - runtime.freeMemory();
    }

    /**
     * Formats a duration in milliseconds to a human-readable string (e.g., "1m 30s
     * 500ms").
     *
     * @param milliseconds Duration to format
     * @return Formatted string representing the duration
     */
    private String formatDuration(long milliseconds) {
        long seconds = milliseconds / 1000;
        long minutes = seconds / 60;
        seconds = seconds % 60;
        milliseconds = milliseconds % 1000;

        return String.format("%dm %ds %dms", minutes, seconds, milliseconds);
    }

    /**
     * Data class for storing performance metrics collected during a test run.
     */
    static class PerformanceMetrics {
        /** Label identifying the test run */
        String testLabel;

        /** Total duration of the scan in milliseconds */
        long durationMs;

        /** Peak memory usage in megabytes */
        double peakMemoryMB;

        /** Average memory usage in megabytes */
        double avgMemoryMB;

        /** Number of files scanned */
        int fileCount;

        /** Number of security violations found */
        int violationCount;

        /** Number of CPU cores available */
        int cpuCores;

        /** Maximum heap size in megabytes */
        long maxHeapMB;
    }
}
