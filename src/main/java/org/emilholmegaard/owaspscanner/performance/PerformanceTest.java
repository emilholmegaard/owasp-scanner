package org.emilholmegaard.owaspscanner.performance;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.ScannerEngine;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.scanners.DotNetScanner;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
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
 * Measures and records scan execution time, memory usage, and other metrics.
 */
public class PerformanceTest {
    private static final Runtime runtime = Runtime.getRuntime();
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    
    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: PerformanceTest <test_directory> <output_csv> [test_label]");
            System.out.println("  test_directory  - Directory containing test files to scan");
            System.out.println("  output_csv      - Path to CSV file to append results to");
            System.out.println("  test_label      - Optional label for this test run (e.g., 'baseline' or 'after-fix-123')");
            return;
        }
        
        String testDir = args[0];
        String outputFile = args[1];
        
        // Optional test label
        String testLabel = args.length > 2 ? args[2] : "unlabeled";
        
        try {
            runPerformanceTest(testDir, outputFile, testLabel);
        } catch (Exception e) {
            System.err.println("Error running performance test: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Runs a performance test on the specified directory and records results.
     * 
     * @param testDirectory Directory to scan
     * @param outputCsv CSV file to append results to
     * @param testLabel Label to identify this test run
     */
    public static void runPerformanceTest(String testDirectory, String outputCsv, String testLabel) throws IOException {
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
                ZonedDateTime.now().format(TIMESTAMP_FORMATTER),
                metrics.testLabel,
                directoryPath.toString().replace(",", ";"), // Escape commas in path
                metrics.durationMs,
                metrics.peakMemoryMB,
                metrics.avgMemoryMB,
                metrics.fileCount,
                metrics.violationCount,
                metrics.cpuCores,
                metrics.maxHeapMB
            ));
            
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
     * Performs the scan and measures performance metrics.
     * 
     * @param directoryPath Directory to scan
     * @return Collected performance metrics
     */
    private static PerformanceMetrics testScanPerformance(Path directoryPath) throws IOException, InterruptedException {
        // Set up the scanner
        ScannerEngine engine = new BaseScannerEngine();
        engine.registerScanner(new DotNetScanner());
        
        // Create a file counter
        AtomicInteger fileCounter = new AtomicInteger(0);
        
        // Count files before scanning to get accurate file count
        Files.walk(directoryPath)
            .filter(Files::isRegularFile)
            .forEach(path -> fileCounter.incrementAndGet());
        
        // Force GC to get more accurate memory measurements
        System.gc();
        Thread.sleep(100); // Short pause to let GC complete
        
        // Get initial memory
        long initialMemory = getUsedMemory();
        long peakMemory = initialMemory;
        
        // Setup memory sampling
        List<Long> memorySamples = new ArrayList<>();
        memorySamples.add(initialMemory);
        
        // Start timing
        Instant start = Instant.now();
        
        // Run the scan
        List<SecurityViolation> violations = engine.scanDirectory(directoryPath);
        
        // End timing
        Instant end = Instant.now();
        
        // Check peak memory one more time
        long currentMemory = getUsedMemory();
        memorySamples.add(currentMemory);
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
     * Gets the currently used memory in bytes.
     */
    private static long getUsedMemory() {
        return runtime.totalMemory() - runtime.freeMemory();
    }
    
    /**
     * Formats duration in milliseconds to a human-readable string.
     */
    private static String formatDuration(long milliseconds) {
        long seconds = milliseconds / 1000;
        long minutes = seconds / 60;
        seconds = seconds % 60;
        milliseconds = milliseconds % 1000;
        
        return String.format("%dm %ds %dms", minutes, seconds, milliseconds);
    }
    
    /**
     * Class to hold performance metrics.
     */
    static class PerformanceMetrics {
        String testLabel;
        long durationMs;
        double peakMemoryMB;
        double avgMemoryMB;
        int fileCount;
        int violationCount;
        int cpuCores;
        long maxHeapMB;
    }
}
