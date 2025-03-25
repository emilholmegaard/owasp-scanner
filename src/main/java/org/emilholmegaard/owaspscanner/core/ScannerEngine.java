package org.emilholmegaard.owaspscanner.core;

import java.nio.file.Path;
import java.util.List;

/**
 * A scanner engine that orchestrates the scanning process.
 */
public interface ScannerEngine {
    /**
     * Registers a scanner with this engine.
     *
     * @param scanner The scanner to register
     */
    void registerScanner(SecurityScanner scanner);
    
    /**
     * Scans a directory recursively for security violations.
     *
     * @param directoryPath Path to the directory to scan
     * @return List of security violations found
     */
    List<SecurityViolation> scanDirectory(Path directoryPath);
    
    /**
     * Scans a single file for security violations.
     *
     * @param filePath Path to the file to scan
     * @return List of security violations found
     */
    List<SecurityViolation> scanFile(Path filePath);
    
    /**
     * Exports the scan results to a JSON file.
     *
     * @param violations The violations to export
     * @param outputPath The path to write the JSON file to
     */
    void exportToJson(List<SecurityViolation> violations, Path outputPath);
    
    /**
     * Sets the configuration for this scanner engine.
     *
     * @param config The configuration to use
     */
    void setConfig(ScannerConfig config);
    
    /**
     * Gets the current configuration for this scanner engine.
     *
     * @return The current scanner configuration
     */
    ScannerConfig getConfig();
}
