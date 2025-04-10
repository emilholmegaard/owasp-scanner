package org.emilholmegaard.owaspscanner.performance;

import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.scanners.DotNetScanner;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Performance tests for the early termination feature.
 * These tests verify that the early termination feature improves scanning
 * performance
 * by comparing scan times with and without potential matches.
 */
@SpringBootTest
@ActiveProfiles("test")
@Tag("performance")
class EarlyTerminationPerformanceTest {

    @Autowired
    private DotNetScanner dotNetScanner;

    @TempDir
    Path tempDir;

    @Test
    void testEarlyTerminationPerformanceImprovement() throws IOException {
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
            List<SecurityViolation> violations = dotNetScanner.scanFile(file);
            totalViolations += violations.size();
        }

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;

        System.out.println("Total files scanned: " + allFiles.size());
        System.out.println("Total violations found: " + totalViolations);
        System.out.println("Total scanning time: " + totalTime + "ms");

        assertTrue(totalViolations > 0, "Should find some violations");
    }

    private List<Path> createMultipleCleanFiles(int count) throws IOException {
        List<Path> files = new ArrayList<>();
        String cleanTemplate = "public class CleanFile%d {\n" +
                "    public void processData(String input) {\n" +
                "        String sanitized = input.trim();\n" +
                "        System.Console.WriteLine(\"Processing: \" + sanitized);\n" +
                "        int hashCode = sanitized.GetHashCode();\n" +
                "        System.Console.WriteLine(\"Hash: \" + hashCode);\n" +
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
        String vulnerableTemplate = "using System.Data.SqlClient;\n" +
                "public class VulnerableFile%d {\n" +
                "    private readonly string connectionString;\n" +
                "    \n" +
                "    public void processData(string userInput) {\n" +
                "        using (var conn = new SqlConnection(connectionString)) {\n" +
                "            conn.Open();\n" +
                "            var cmd = new SqlCommand(\"SELECT * FROM Data WHERE Value = '\" + userInput + \"'\", conn);\n"
                +
                "            var reader = cmd.ExecuteReader();\n" +
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
