package org.emilholmegaard.owaspscanner.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Default implementation of the ScannerEngine interface.
 */
public class BaseScannerEngine implements ScannerEngine {
    private final List<SecurityScanner> scanners = new ArrayList<>();
    
    @Override
    public void registerScanner(SecurityScanner scanner) {
        scanners.add(scanner);
    }
    
    @Override
    public List<SecurityViolation> scanDirectory(Path directoryPath) {
        List<SecurityViolation> allViolations = new ArrayList<>();
        
        try {
            Files.walk(directoryPath)
                .filter(Files::isRegularFile)
                .forEach(filePath -> allViolations.addAll(scanFile(filePath)));
        } catch (IOException e) {
            System.err.println("Error scanning directory: " + e.getMessage());
            e.printStackTrace();
        }
        
        return allViolations;
    }
    
    @Override
    public List<SecurityViolation> scanFile(Path filePath) {
        List<SecurityViolation> violations = new ArrayList<>();
        
        // Find appropriate scanner for this file
        for (SecurityScanner scanner : scanners) {
            if (scanner.canProcessFile(filePath)) {
                try {
                    List<SecurityViolation> fileViolations = scanner.scanFile(filePath);
                    violations.addAll(fileViolations);
                } catch (Exception e) {
                    System.err.println("Error scanning file " + filePath + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
        
        return violations;
    }
    
    @Override
    public void exportToJson(List<SecurityViolation> violations, Path outputPath) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        String json = gson.toJson(violations);
        
        try {
            Files.createDirectories(outputPath.getParent());
            Files.writeString(outputPath, json);
            System.out.println("Scan results exported to " + outputPath);
        } catch (IOException e) {
            System.err.println("Error exporting results to JSON: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Default implementation of RuleContext.
     */
    public static class DefaultRuleContext implements RuleContext {
        private final Path filePath;
        private final List<String> fileContent;
        
        public DefaultRuleContext(Path filePath) {
            this.filePath = filePath;
            try {
                this.fileContent = Files.readAllLines(filePath);
            } catch (IOException e) {
                throw new RuntimeException("Failed to read file: " + filePath, e);
            }
        }
        
        @Override
        public Path getFilePath() {
            return filePath;
        }
        
        @Override
        public List<String> getFileContent() {
            return fileContent;
        }
        
        @Override
        public List<String> getLinesAround(int lineNumber, int windowSize) {
            int start = Math.max(0, lineNumber - windowSize - 1);
            int end = Math.min(fileContent.size(), lineNumber + windowSize);
            
            return fileContent.subList(start, end);
        }
    }
}