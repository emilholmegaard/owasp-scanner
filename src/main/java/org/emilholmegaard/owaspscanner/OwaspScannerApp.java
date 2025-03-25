package org.emilholmegaard.owaspscanner;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.ScannerConfig;
import org.emilholmegaard.owaspscanner.core.ScannerEngine;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.scanners.DotNetScanner;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

/**
 * Main application class for the OWASP Scanner.
 */
public class OwaspScannerApp {
    public static void main(String[] args) {
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
                
                // Parse performance configuration from arguments
                ScannerConfig config = parseScannerConfig(args);
                
                runScan(directoryPath, outputPath, config);
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
     * Parse command line arguments to create a scanner configuration
     * 
     * @param args Command line arguments
     * @return ScannerConfig based on provided arguments or default
     */
    private static ScannerConfig parseScannerConfig(String[] args) {
        ScannerConfig config;
        
        if (Arrays.asList(args).contains("--fast")) {
            config = ScannerConfig.fastConfig();
            System.out.println("Using fast scan configuration");
        } else if (Arrays.asList(args).contains("--thorough")) {
            config = ScannerConfig.thoroughConfig();
            System.out.println("Using thorough scan configuration");
        } else {
            config = ScannerConfig.defaultConfig();
            System.out.println("Using default scan configuration");
        }
        
        // Parse other performance arguments
        for (String arg : args) {
            if (arg.startsWith("--threads=")) {
                try {
                    int threads = Integer.parseInt(arg.substring("--threads=".length()));
                    config.setMaxThreads(threads);
                    System.out.println("Using " + threads + " threads for scanning");
                } catch (NumberFormatException e) {
                    // Use default
                }
            } else if (arg.startsWith("--max-file-size=")) {
                try {
                    int maxSizeMb = Integer.parseInt(arg.substring("--max-file-size=".length()));
                    config.setMaxFileSizeBytes(maxSizeMb * 1024 * 1024L);
                    System.out.println("Maximum file size set to " + maxSizeMb + "MB");
                } catch (NumberFormatException e) {
                    // Use default
                }
            } else if (arg.startsWith("--max-violations=")) {
                try {
                    int maxViolations = Integer.parseInt(arg.substring("--max-violations=".length()));
                    config.setMaxViolationsPerFile(maxViolations);
                    System.out.println("Maximum violations per file set to " + maxViolations);
                } catch (NumberFormatException e) {
                    // Use default
                }
            } else if (arg.equals("--no-cache")) {
                config.setCacheFileContent(false);
                System.out.println("File content caching disabled");
            } else if (arg.equals("--no-parallel")) {
                config.setParallelProcessing(false);
                System.out.println("Parallel processing disabled");
            } else if (arg.equals("--no-early-termination")) {
                config.setEarlyTermination(false);
                System.out.println("Early termination disabled");
            }
        }
        
        return config;
    }
    
    private static void runScan(String directoryPath, String outputPath, ScannerConfig config) {
        System.out.println("Starting scan of directory: " + directoryPath);
        
        // Initialize scanner engine
        ScannerEngine engine = new BaseScannerEngine();
        
        // Set configuration
        engine.setConfig(config);
        
        // Register available scanners
        DotNetScanner dotNetScanner = new DotNetScanner();
        engine.registerScanner(dotNetScanner);
        
        // Normalize path for cross-platform compatibility
        Path normalizedPath = Paths.get(directoryPath).normalize();
        
        // Verify directory exists
        File dirFile = normalizedPath.toFile();
        if (!dirFile.exists()) {
            System.err.println("Error: Directory does not exist: " + normalizedPath);
            return;
        }
        if (!dirFile.isDirectory()) {
            System.err.println("Error: Path is not a directory: " + normalizedPath);
            return;
        }
        
        // Run the scan
        List<SecurityViolation> violations = engine.scanDirectory(normalizedPath);
        
        // Print summary
        System.out.println("\nScan completed. Found " + violations.size() + " potential security issues.");
        
        // Export results
        try {
            Path outputFilePath = Paths.get(outputPath).normalize();
            engine.exportToJson(violations, outputFilePath);
        } catch (Exception e) {
            System.err.println("Error exporting results: " + e.getMessage());
            System.err.println("Results will not be saved to file.");
        }
        
        // Print categorized summary
        printSummary(violations);
    }
    
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
                    String filename = v.getFilePath().getFileName() != null ?
                        v.getFilePath().getFileName().toString() : "<unknown file>";
                    System.out.println("- " + v.getRuleId() + ": " + 
                        v.getDescription() + " in " + filename + 
                        " (line " + v.getLineNumber() + ")");
                });
        }
    }
    
    private static void printUsage() {
        System.out.println("OWASP Scanner - Security scanner based on OWASP Cheat Sheet Series");
        System.out.println("\nUsage:");
        System.out.println("  java -jar owasp-scanner.jar scan <directory> [output-file] [options]");
        System.out.println("  java -jar owasp-scanner.jar help");
        System.out.println("\nCommands:");
        System.out.println("  scan         Scan a directory for security issues");
        System.out.println("  help         Show this help message");
        System.out.println("\nArguments:");
        System.out.println("  directory    Path to the directory to scan");
        System.out.println("  output-file  Path to write the JSON results (default: scan_results.json)");
        System.out.println("\nOptions:");
        System.out.println("  --fast                   Use optimized settings for speed");
        System.out.println("  --thorough               Use thorough settings for complete scanning");
        System.out.println("  --threads=N              Use N threads for scanning");
        System.out.println("  --max-file-size=N        Maximum file size to scan in MB");
        System.out.println("  --max-violations=N       Maximum violations to collect per file");
        System.out.println("  --no-cache               Disable file content caching");
        System.out.println("  --no-parallel            Disable parallel processing");
        System.out.println("  --no-early-termination   Scan entire files even when violation threshold is reached");
    }
}
