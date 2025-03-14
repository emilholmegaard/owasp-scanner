package org.emilholmegaard.owaspscanner.core;

import java.nio.file.Path;
import java.util.List;

/**
 * Interface for all technology-specific scanners.
 */
public interface SecurityScanner {
    /**
     * Returns the name of the scanner.
     */
    String getName();
    
    /**
     * Returns the technology this scanner is designed for.
     */
    String getTechnology();
    
    /**
     * Returns the list of file extensions this scanner can process.
     */
    List<String> getSupportedFileExtensions();
    
    /**
     * Scans a single file for security violations.
     *
     * @param filePath Path to the file to scan
     * @return List of security violations found in the file
     */
    List<SecurityViolation> scanFile(Path filePath);
    
    /**
     * Checks if the scanner can process the given file based on its extension.
     *
     * @param filePath Path to the file to check
     * @return true if the scanner can process this file, false otherwise
     */
    default boolean canProcessFile(Path filePath) {
        String fileName = filePath.getFileName().toString().toLowerCase();
        return getSupportedFileExtensions().stream()
                .anyMatch(ext -> fileName.endsWith("." + ext.toLowerCase()));
    }
}