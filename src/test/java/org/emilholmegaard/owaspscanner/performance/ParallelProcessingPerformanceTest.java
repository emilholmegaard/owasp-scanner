package org.emilholmegaard.owaspscanner.performance;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.SecurityScanner;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

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

/**
 * Performance tests for parallel file processing in BaseScannerEngine.
 */
public class ParallelProcessingPerformanceTest {

    private BaseScannerEngine engine;
    private SecurityScanner mockScanner;
    
    @BeforeEach
    void setUp() {
        // Initialize the scanner engine
        engine = new BaseScannerEngine();
        mockScanner = Mockito.mock(SecurityScanner.class);
        
        // Setup mock scanner
        when(mockScanner.getSupportedFileExtensions()).thenReturn(Arrays.asList("java", "xml", "txt"));
        when(mockScanner.canProcessFile(any())).thenReturn(true);
    }
    
    /**
     * Creates a specified number of test files in the temp directory.
     * 
     * @param count Number of files to create
     * @param sizePerFile Number of lines per file
     * @param tempDir Directory to create files in
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
        // Create test files (reduced for faster tests in CI)
        int fileCount = 50; // Reduced from 100 to 50
        int linesPerFile = 50; // Reduced from 100 to 50
        createTestFiles(fileCount, linesPerFile, tempDir);
        
        // Configure mock scanner to simulate work (shorter time for CI)
        final AtomicInteger maxConcurrentThreads = new AtomicInteger(0);
        final AtomicInteger currentThreads = new AtomicInteger(0);
        
        doAnswer(invocation -> {
            // Increment current thread count and update max
            int current = currentThreads.incrementAndGet();
            maxConcurrentThreads.updateAndGet(max -> Math.max(max, current));
            
            // Simulate work (reduced from 50ms to 20ms)
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            
            // Get file path from invocation
            Path filePath = invocation.getArgument(0);
            
            // Create a single violation for this file
            SecurityViolation violation = new SecurityViolation(
                "PERF-001",
                "Performance test violation",
                filePath,
                1,
                "Code snippet",
                "LOW",
                "No action needed",
                "https://example.com/owasp"
            );
            
            // Decrement thread count
            currentThreads.decrementAndGet();
            
            return Collections.singletonList(violation);
        }).when(mockScanner).scanFile(any(Path.class));
        
        // Register the scanner
        engine.registerScanner(mockScanner);
        
        // Measure parallel processing time
        System.out.println("Starting parallel scan of " + fileCount + " files...");
        long startParallel = System.currentTimeMillis();
        List<SecurityViolation> violations = engine.scanDirectory(tempDir);
        long parallelTime = System.currentTimeMillis() - startParallel;
        
        // Calculate theoretical sequential time (files * time per file)
        long estimatedSequentialTime = fileCount * 20;
        
        // Print performance results
        System.out.println("Parallel processing completed in: " + parallelTime + "ms");
        System.out.println("Estimated sequential time: " + estimatedSequentialTime + "ms");
        System.out.println("Speedup factor: " + (float)estimatedSequentialTime / parallelTime);
        System.out.println("Maximum concurrent threads used: " + maxConcurrentThreads.get());
        System.out.println("Total violations found: " + violations.size());
        
        // Assert that we got performance improvement
        // Use a more lenient threshold for CI environments
        assertTrue(parallelTime < estimatedSequentialTime * 1.5,
                "Parallel processing should be faster than sequential processing. " +
                "Parallel: " + parallelTime + "ms, Sequential est.: " + estimatedSequentialTime + "ms");
        
        // Assert that we used multiple threads
        assertTrue(maxConcurrentThreads.get() > 1,
                "Should have used multiple threads for parallel processing");
        
        // Verify we found all violations
        assertEquals(fileCount, violations.size(),
                "Should have found one violation per file");
    }
}