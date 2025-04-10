package org.emilholmegaard.owaspscanner.performance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Analyzes performance test results and generates summary reports.
 * Can be used to compare different test runs and track improvements over time.
 */
public class PerformanceSummary {

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: PerformanceSummary <results_csv> [baseline_label] [comparison_label]");
            System.out.println("  results_csv      - Path to the CSV file with performance results");
            System.out.println("  baseline_label    - Optional: Label of the baseline test to compare against");
            System.out.println("  comparison_label  - Optional: Label of the test to compare with baseline");
            System.out.println("\nIf labels are not provided, the most recent runs will be used for comparison.");
            return;
        }

        String csvFile = args[0];
        String baselineLabel = args.length > 1 ? args[1] : null;
        String comparisonLabel = args.length > 2 ? args[2] : null;

        try {
            generateSummary(csvFile, baselineLabel, comparisonLabel);
        } catch (IOException e) {
            System.err.println("Error generating performance summary: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Generates a performance summary report from the given CSV file.
     * 
     * @param csvFile         Path to the CSV file with performance results
     * @param baselineLabel   Optional label for baseline test run
     * @param comparisonLabel Optional label for comparison test run
     */
    public static void generateSummary(String csvFile, String baselineLabel, String comparisonLabel)
            throws IOException {
        Path csvPath = Paths.get(csvFile);

        if (!Files.exists(csvPath)) {
            System.out.println("Results file not found: " + csvFile);
            return;
        }

        List<String> lines = Files.readAllLines(csvPath);

        if (lines.size() <= 1) {
            System.out.println("Not enough data to generate summary. File contains only " +
                    lines.size() + " line(s).");
            return;
        }

        // Skip header
        List<PerformanceEntry> entries = new ArrayList<>();
        for (int i = 1; i < lines.size(); i++) {
            String[] parts = lines.get(i).split(",");
            if (parts.length >= 9) {
                try {
                    PerformanceEntry entry = new PerformanceEntry();
                    entry.timestamp = parts[0];
                    entry.testLabel = parts[1];
                    entry.directory = parts[2];
                    entry.durationMs = Long.parseLong(parts[3]);
                    entry.peakMemoryMB = Double.parseDouble(parts[4]);
                    entry.avgMemoryMB = Double.parseDouble(parts[5]);
                    entry.fileCount = Integer.parseInt(parts[6]);
                    entry.violationCount = Integer.parseInt(parts[7]);
                    entry.cpuCores = Integer.parseInt(parts[8]);

                    if (parts.length > 9) {
                        entry.maxHeapMB = Long.parseLong(parts[9]);
                    }

                    entries.add(entry);
                } catch (NumberFormatException e) {
                    System.out.println("Warning: Skipping malformed line: " + lines.get(i));
                }
            } else {
                System.out.println("Warning: Skipping line with insufficient data: " + lines.get(i));
            }
        }

        // Group entries by test label
        Map<String, List<PerformanceEntry>> entriesByLabel = entries.stream()
                .collect(Collectors.groupingBy(e -> e.testLabel));

        // Print summary header
        System.out.println("\nPerformance Summary");
        System.out.println("==================");
        System.out.println("Total test runs: " + entries.size());
        System.out.println("Unique test labels: " + entriesByLabel.size());
        System.out.println("Available labels: " + String.join(", ", entriesByLabel.keySet()));

        // Calculate latest results by label
        Map<String, PerformanceEntry> latestByLabel = new HashMap<>();
        for (String label : entriesByLabel.keySet()) {
            List<PerformanceEntry> labelEntries = entriesByLabel.get(label);
            // Sort by timestamp (descending) and take the most recent
            labelEntries.sort(Comparator.comparing(e -> e.timestamp, Comparator.reverseOrder()));
            latestByLabel.put(label, labelEntries.get(0));
        }

        // Pick baseline and comparison entries
        PerformanceEntry baseline;
        PerformanceEntry comparison;

        if (baselineLabel != null && comparisonLabel != null) {
            // Use specified labels
            baseline = latestByLabel.get(baselineLabel);
            comparison = latestByLabel.get(comparisonLabel);

            if (baseline == null) {
                System.out.println("\nError: Baseline label '" + baselineLabel + "' not found in results.");
                return;
            }
            if (comparison == null) {
                System.out.println("\nError: Comparison label '" + comparisonLabel + "' not found in results.");
                return;
            }
        } else {
            // Use most recent entries
            // Sort all entries by timestamp (descending)
            entries.sort(Comparator.comparing(e -> e.timestamp, Comparator.reverseOrder()));

            if (entries.size() >= 2) {
                comparison = entries.get(0); // Most recent
                baseline = entries.get(1); // Second most recent
            } else {
                comparison = entries.get(0);
                baseline = comparison; // Same entry, no comparison possible
            }
        }

        // Print overall summary table
        System.out.println("\nOverall Summary (most recent run per label):");
        System.out.println("--------------------------------------------");
        System.out.printf("%-20s %-15s %-15s %-15s %-15s\n", "Test Label", "Duration", "Peak Memory", "Violations",
                "Files");
        System.out.printf("%-20s %-15s %-15s %-15s %-15s\n", "----------", "--------", "-----------", "----------",
                "-----");

        for (String label : latestByLabel.keySet()) {
            PerformanceEntry entry = latestByLabel.get(label);
            System.out.printf("%-20s %-15s %-15.2f %-15d %-15d\n",
                    truncateString(entry.testLabel, 20),
                    formatDuration(entry.durationMs),
                    entry.peakMemoryMB,
                    entry.violationCount,
                    entry.fileCount);
        }

        // Print comparison (if we have different entries)
        if (!baseline.equals(comparison)) {
            System.out.println("\nComparison Analysis:");
            System.out.println("-------------------");
            System.out.println("Baseline: " + baseline.testLabel + " (" + baseline.timestamp + ")");
            System.out.println("Comparison: " + comparison.testLabel + " (" + comparison.timestamp + ")");

            // Calculate differences
            double durationDiff = 100 * (baseline.durationMs - comparison.durationMs) / (double) baseline.durationMs;
            double memoryDiff = 100 * (baseline.peakMemoryMB - comparison.peakMemoryMB) / baseline.peakMemoryMB;

            System.out.println("\nPerformance Change:");
            System.out.printf("  Time: %+.2f%% (%s -> %s)\n",
                    durationDiff,
                    formatDuration(baseline.durationMs),
                    formatDuration(comparison.durationMs));
            System.out.printf("  Memory: %+.2f%% (%.2f MB -> %.2f MB)\n",
                    memoryDiff,
                    baseline.peakMemoryMB,
                    comparison.peakMemoryMB);

            // Interpretation
            System.out.println("\nInterpretation:");
            if (durationDiff > 0) {
                System.out.println("  ✓ Execution time decreased by " + String.format("%.2f", durationDiff) + "%");
            } else if (durationDiff < 0) {
                System.out.println("  ✗ Execution time increased by " + String.format("%.2f", -durationDiff) + "%");
            } else {
                System.out.println("  ○ Execution time unchanged");
            }

            if (memoryDiff > 0) {
                System.out.println("  ✓ Memory usage decreased by " + String.format("%.2f", memoryDiff) + "%");
            } else if (memoryDiff < 0) {
                System.out.println("  ✗ Memory usage increased by " + String.format("%.2f", -memoryDiff) + "%");
            } else {
                System.out.println("  ○ Memory usage unchanged");
            }
        }
    }

    /**
     * Formats duration in milliseconds to a human-readable string.
     */
    private static String formatDuration(long milliseconds) {
        long seconds = milliseconds / 1000;
        long minutes = seconds / 60;
        seconds = seconds % 60;

        if (minutes > 0) {
            return String.format("%dm %02ds", minutes, seconds);
        } else {
            return String.format("%.3fs", milliseconds / 1000.0);
        }
    }

    /**
     * Truncates a string to a maximum length, adding ellipsis if needed.
     */
    private static String truncateString(String str, int maxLength) {
        if (str.length() <= maxLength) {
            return str;
        }
        return str.substring(0, maxLength - 3) + "...";
    }

    /**
     * Class to hold performance entry data from CSV.
     */
    static class PerformanceEntry {
        String timestamp;
        String testLabel;
        String directory;
        long durationMs;
        double peakMemoryMB;
        double avgMemoryMB;
        int fileCount;
        int violationCount;
        int cpuCores;
        long maxHeapMB;
    }
}
