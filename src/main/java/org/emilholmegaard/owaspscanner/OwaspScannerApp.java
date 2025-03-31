package org.emilholmegaard.owaspscanner;

import org.emilholmegaard.owaspscanner.core.ScannerEngine;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Main application class for the OWASP Scanner.
 * This scanner analyzes source code for potential security vulnerabilities
 * based on OWASP security guidelines.
 */
@SpringBootApplication
public class OwaspScannerApp implements CommandLineRunner {

    private final ScannerEngine scannerEngine;

    /**
     * Constructs a new OWASP Scanner application with the specified scanner engine.
     *
     * @param scannerEngine The engine responsible for performing security scans
     */
    @Autowired
    public OwaspScannerApp(ScannerEngine scannerEngine) {
        this.scannerEngine = scannerEngine;
    }

    /**
     * Application entry point.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(OwaspScannerApp.class, args);
    }

    /**
     * Executes the scanner based on command line arguments.
     * Supports 'scan' and 'help' commands.
     *
     * @param args Command line arguments
     */
    @Override
    public void run(String... args) {
        if (args.length < 1) {
            printUsage();
            return;
        }

        String command = args[0];

        switch (command) {
            case "scan":
                if (args.length < 2) {
                    System.out.println("Error: Missing directory path to scan");
                    printUsage();
                    return;
                }
                String directoryPath = args[1];
                String outputPath = args.length > 2 ? args[2] : "scan_results.json";

                this.runScan(directoryPath, outputPath);
                break;

            case "help":
                printUsage();
                break;

            default:
                System.out.println("Unknown command: " + command);
                printUsage();
                break;
        }
    }

    /**
     * Performs a security scan on the specified directory and exports results.
     *
     * @param directoryPath The path to the directory to scan
     * @param outputPath    The path where to save the scan results
     */
    private void runScan(String directoryPath, String outputPath) {
        Path normalizedPath = Paths.get(directoryPath).normalize();

        // Run the scan
        List<SecurityViolation> violations = scannerEngine.scanDirectory(normalizedPath);

        // Export results
        try {
            Path outputFilePath = Paths.get(outputPath).normalize();
            scannerEngine.exportToJson(violations, outputFilePath);
        } catch (Exception e) {
            System.err.println("Error exporting results: " + e.getMessage());
        }

        // Print summary
        printSummary(violations);

    }

    /**
     * Prints a summary of security violations found during the scan.
     * Groups violations by severity level and shows top critical/high issues.
     *
     * @param violations List of security violations found during the scan
     */
    private static void printSummary(List<SecurityViolation> violations) {
        long criticalCount = violations.stream()
                .filter(v -> "CRITICAL".equals(v.getSeverity()))
                .count();

        long highCount = violations.stream()
                .filter(v -> "HIGH".equals(v.getSeverity()))
                .count();

        long mediumCount = violations.stream()
                .filter(v -> "MEDIUM".equals(v.getSeverity()))
                .count();

        long lowCount = violations.stream()
                .filter(v -> "LOW".equals(v.getSeverity()))
                .count();

        System.out.println("\nSecurity Issues Summary:");
        System.out.println("------------------------");
        System.out.println("CRITICAL: " + criticalCount);
        System.out.println("HIGH: " + highCount);
        System.out.println("MEDIUM: " + mediumCount);
        System.out.println("LOW: " + lowCount);

        if (violations.size() > 0) {
            System.out.println("\nTop issues to address first:");
            violations.stream()
                    .filter(v -> "CRITICAL".equals(v.getSeverity()) || "HIGH".equals(v.getSeverity()))
                    .limit(5)
                    .forEach(v -> {
                        String filename = v.getFilePath().getFileName() != null
                                ? v.getFilePath().getFileName().toString()
                                : "<unknown file>";
                        System.out.println("- " + v.getRuleId() + ": " +
                                v.getDescription() + " in " + filename +
                                " (line " + v.getLineNumber() + ")");
                    });
        }
    }

    /**
     * Prints usage instructions for the scanner application.
     * Shows available commands and their parameters.
     */
    private static void printUsage() {
        System.out.println("OWASP Scanner - Security scanner based on OWASP Cheat Sheet Series");
        System.out.println("\nUsage:");
        System.out.println("  java -jar owasp-scanner.jar scan <directory> [output-file]");
        System.out.println("  java -jar owasp-scanner.jar help");
        System.out.println("\nCommands:");
        System.out.println("  scan         Scan a directory for security issues");
        System.out.println("  help         Show this help message");
        System.out.println("\nArguments:");
        System.out.println("  directory    Path to the directory to scan");
        System.out.println("  output-file  Path to write the JSON results (default: scan_results.json)");
    }
}