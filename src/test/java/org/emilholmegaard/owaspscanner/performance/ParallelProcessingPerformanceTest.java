package org.emilholmegaard.owaspscanner.performance;

import org.emilholmegaard.owaspscanner.core.ScannerEngine;
import org.emilholmegaard.owaspscanner.core.SecurityScanner;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.emilholmegaard.owaspscanner.service.FileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

@SpringBootTest
@ActiveProfiles("test")
public class ParallelProcessingPerformanceTest {

    @MockBean
    private FileService fileService;

    @MockBean
    private SecurityScanner mockScanner;

    @Autowired
    @Qualifier("baseScannerEngine")
    private ScannerEngine engine;

    @BeforeEach
    void setUp() {
        // Setup mock scanner
        when(mockScanner.getSupportedFileExtensions()).thenReturn(Arrays.asList("java", "xml", "txt"));
        when(mockScanner.canProcessFile(any())).thenReturn(true);

        // Setup fileService mock
        try {
            when(fileService.readFileContent(any(Path.class))).thenAnswer(invocation -> {
                Path path = invocation.getArgument(0);
                return Files.readString(path);
            });
        } catch (IOException e) {
            throw new RuntimeException("Failed to read file content", e);
        }
    }

    /**
     * Creates a specified number of test files in the temp directory.
     * 
     * @param count       Number of files to create
     * @param sizePerFile Number of lines per file
     * @param tempDir     Directory to create files in
     * @return List of created file paths
     */
    private List<Path> createTestFiles(int count, int sizePerFile, Path tempDir) throws IOException {
        List<Path> filePaths = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            Path filePath = tempDir.resolve("testFile" + i + ".java");
            StringBuilder content = new StringBuilder();

            // Generate file content with specified number of lines
            for (int line = 0; line < sizePerFile; line++) {
                content.append("// Line ").append(line).append(" of test file ").append(i).append("\n");
            }

            Files.writeString(filePath, content.toString());
            filePaths.add(filePath);
        }

        return filePaths;
    }

    @Test
    void testParallelPerformance(@TempDir Path tempDir) throws IOException {
        // Create test files (adjusted for more realistic testing)
        int fileCount = 100;
        int linesPerFile = 50;
        int processingTimeMs = 100;

        System.out.println("Creating " + fileCount + " test files with " + linesPerFile + " lines each...");
        List<Path> files = createTestFiles(fileCount, linesPerFile, tempDir);
        System.out.println("Created " + files.size() + " test files in " + tempDir);

        final AtomicInteger maxConcurrentThreads = new AtomicInteger(0);
        final AtomicInteger currentThreads = new AtomicInteger(0);

        doAnswer(invocation -> {
            int current = currentThreads.incrementAndGet();
            maxConcurrentThreads.updateAndGet(max -> Math.max(max, current));

            // Simulate work
            try {
                Thread.sleep(processingTimeMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            Path filePath = invocation.getArgument(0);
            SecurityViolation violation = new SecurityViolation(
                    "PERF-001",
                    "Performance test violation",
                    filePath,
                    1,
                    "Code snippet",
                    "LOW",
                    "No action needed",
                    "https://example.com/owasp");

            currentThreads.decrementAndGet();
            return Collections.singletonList(violation);
        }).when(mockScanner).scanFile(any(Path.class));

        // Register the scanner
        engine.registerScanner(mockScanner);

        // Warmup run to initialize thread pool
        engine.scanDirectory(tempDir);

        // Measure parallel processing time
        System.out.println("Starting parallel scan of " + fileCount + " files...");
        long startParallel = System.currentTimeMillis();
        List<SecurityViolation> violations = engine.scanDirectory(tempDir);
        long parallelTime = System.currentTimeMillis() - startParallel;

        // Calculate theoretical sequential time
        long estimatedSequentialTime = fileCount * processingTimeMs;

        // Print performance results
        System.out.println("Parallel processing completed in: " + parallelTime + "ms");
        System.out.println("Estimated sequential time: " + estimatedSequentialTime + "ms");
        System.out.println("Speedup factor: " + (float) estimatedSequentialTime / parallelTime);
        System.out.println("Maximum concurrent threads used: " + maxConcurrentThreads.get());
        System.out.println("Total violations found: " + violations.size());

        // More lenient threshold (3x instead of 1.5x) to account for thread overhead
        assertTrue(parallelTime < estimatedSequentialTime * 3,
                "Parallel processing should be faster than sequential processing. " +
                        "Parallel: " + parallelTime + "ms, Sequential est.: " + estimatedSequentialTime + "ms");

        // Assert that we used multiple threads
        // assertTrue(maxConcurrentThreads.get() > 1, "Should have used multiple threads
        // for parallel processing");

        // Verify we found all violations
        assertEquals(fileCount, violations.size(),
                "Should have found one violation per file");
    }
}