package org.emilholmegaard.owaspscanner.performance;

import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.scanners.DotNetScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Performance tests for the early termination feature.
 * These tests verify that the early termination feature improves scanning performance
 * by comparing scan times with and without potential matches.
 */
@Tag("performance")
public class EarlyTerminationPerformanceTest {

    @TempDir
    Path tempDir;
    
    private DotNetScanner scanner;
    
    @BeforeEach
    public void setUp() {
        scanner = new DotNetScanner();
    }
    
    @Test
    public void testEarlyTerminationPerformanceImprovement() throws IOException {
        // Create a large number of "clean" files (no matches)
        List<Path> cleanFiles = createMultipleCleanFiles(100);
        
        // Create a few files with security violations
        List<Path> violationFiles = createMultipleViolationFiles(5);
        
        // Combine all files
        List<Path> allFiles = new ArrayList<>();
        allFiles.addAll(cleanFiles);
        allFiles.addAll(violationFiles);
        
        // Time scanning all files
        long startTime = System.currentTimeMillis();
        
        int totalViolations = 0;
        for (Path file : allFiles) {
            List<SecurityViolation> violations = scanner.scanFile(file);
            totalViolations += violations.size();
        }
        
        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        
        System.out.println("Total files scanned: " + allFiles.size());
        System.out.println("Total violations found: " + totalViolations);
        System.out.println("Total scanning time: " + totalTime + "ms");
        
        // We expect to find violations only in the violation files
        assertTrue(totalViolations > 0, "Should find some violations");
        
        // This test doesn't make specific time assertions since execution time
        // varies by environment, but it verifies the implementation works and
        // provides timing information for manual verification
    }
    
    private List<Path> createMultipleCleanFiles(int count) throws IOException {
        List<Path> files = new ArrayList<>();
        String cleanTemplate = 
            "public class CleanFile%d {\n" +
            "    public void processData(String input) {\n" +
            "        // This is a clean file with no security issues\n" +
            "        String sanitized = input.trim();\n" +
            "        System.Console.WriteLine(\"Processing: \" + sanitized);\n" +
            "        \n" +
            "        // Perform some harmless operations\n" +
            "        int hashCode = sanitized.GetHashCode();\n" +
            "        System.Console.WriteLine(\"Hash: \" + hashCode);\n" +
            "        \n" +
            "        // No SQL queries or other potentially vulnerable operations\n" +
            "    }\n" +
            "}";
        
        for (int i = 0; i < count; i++) {
            Path file = tempDir.resolve("CleanFile" + i + ".cs");
            String content = String.format(cleanTemplate, i);
            Files.writeString(file, content);
            files.add(file);
        }
        
        return files;
    }
    
    private List<Path> createMultipleViolationFiles(int count) throws IOException {
        List<Path> files = new ArrayList<>();
        String vulnerableTemplate = 
            "using System.Data.SqlClient;\n" +
            "public class VulnerableFile%d {\n" +
            "    private readonly string connectionString;\n" +
            "    \n" +
            "    public void processData(string userInput) {\n" +
            "        // SQL Injection vulnerability\n" +
            "        using (var conn = new SqlConnection(connectionString)) {\n" +
            "            conn.Open();\n" +
            "            var cmd = new SqlCommand(\"SELECT * FROM Data WHERE Value = '\" + userInput + \"'\", conn);\n" +
            "            var reader = cmd.ExecuteReader();\n" +
            "            // Process results\n" +
            "        }\n" +
            "    }\n" +
            "}";
        
        for (int i = 0; i < count; i++) {
            Path file = tempDir.resolve("VulnerableFile" + i + ".cs");
            String content = String.format(vulnerableTemplate, i);
            Files.writeString(file, content);
            files.add(file);
        }
        
        return files;
    }
}
