package org.emilholmegaard.owaspscanner.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doAnswer;

class BaseScannerEngineTest {
    
    private BaseScannerEngine engine;
    private SecurityScanner mockScanner;
    
    @BeforeEach
    void setUp() {
        engine = new BaseScannerEngine();
        mockScanner = Mockito.mock(SecurityScanner.class);
        
        // Setup mock scanner
        when(mockScanner.getSupportedFileExtensions()).thenReturn(Arrays.asList("cs", "config"));
        when(mockScanner.canProcessFile(any(Path.class))).thenReturn(false); // Default to false
        when(mockScanner.canProcessFile(Mockito.argThat(path -> 
            path != null && (path.toString().endsWith(".cs") || path.toString().endsWith(".config"))))).thenReturn(true);
    }
    
    @Test
    void testRegisterScanner() {
        engine.registerScanner(mockScanner);
        // Indirectly test by scanning a file that the scanner can process
        when(mockScanner.scanFile(any())).thenReturn(Collections.emptyList());
        
        List<SecurityViolation> results = engine.scanFile(Path.of("test.cs"));
        assertEquals(0, results.size());
        
        // Verify that the scanner's scanFile method was called
        Mockito.verify(mockScanner).scanFile(any());
    }
    
    @Test
    void testScanFile(@TempDir Path tempDir) throws IOException {
        // Create a test file
        Path testFile = tempDir.resolve("test.cs");
        Files.writeString(testFile, "// Test file content");
        
        // Create a mock violation with a simple string path to avoid serialization issues
        SecurityViolation mockViolation = new SecurityViolation(
            "TEST-001", "Test violation", testFile, 1, 
            "Test snippet", "MEDIUM", "Fix it", "example.com");
        
        when(mockScanner.scanFile(testFile)).thenReturn(Collections.singletonList(mockViolation));
        
        // Register scanner and scan the file
        engine.registerScanner(mockScanner);
        List<SecurityViolation> violations = engine.scanFile(testFile);
        
        // Verify
        assertEquals(1, violations.size());
        assertEquals("TEST-001", violations.get(0).getRuleId());
        assertEquals("Test violation", violations.get(0).getDescription());
    }
    
    @Test
    void testScanDirectory(@TempDir Path tempDir) throws IOException {
        // Create test directory structure with multiple files
        Path file1 = tempDir.resolve("file1.cs");
        Path file2 = tempDir.resolve("file2.config");
        Path file3 = tempDir.resolve("file3.txt"); // Not supported by the scanner
        
        Files.writeString(file1, "// CS file");
        Files.writeString(file2, "<!-- Config file -->");
        Files.writeString(file3, "Plain text file");
        
        // Setup mock violations
        SecurityViolation violation1 = new SecurityViolation(
            "TEST-001", "Violation in CS file", file1, 1, 
            "CS file", "HIGH", "Fix it", "example.com");
        SecurityViolation violation2 = new SecurityViolation(
            "TEST-002", "Violation in config file", file2, 1, 
            "Config file", "MEDIUM", "Fix it", "example.com");
        
        when(mockScanner.scanFile(file1)).thenReturn(Collections.singletonList(violation1));
        when(mockScanner.scanFile(file2)).thenReturn(Collections.singletonList(violation2));
        
        // Register scanner and scan the directory
        engine.registerScanner(mockScanner);
        List<SecurityViolation> violations = engine.scanDirectory(tempDir);
        
        // Verify
        assertEquals(2, violations.size());
        assertTrue(violations.stream().anyMatch(v -> v.getRuleId().equals("TEST-001")));
        assertTrue(violations.stream().anyMatch(v -> v.getRuleId().equals("TEST-002")));
    }
    
    @Test
    void testParallelFileProcessing(@TempDir Path tempDir) throws IOException, InterruptedException {
        // Create multiple test files
        int fileCount = 10;
        for (int i = 0; i < fileCount; i++) {
            Path file = tempDir.resolve("file" + i + ".cs");
            Files.writeString(file, "// CS file " + i);
        }
        
        // Create a countdown latch to verify parallel execution
        CountDownLatch latch = new CountDownLatch(fileCount);
        
        // Track the maximum number of concurrent threads used
        AtomicInteger concurrentThreads = new AtomicInteger(0);
        AtomicInteger maxConcurrentThreads = new AtomicInteger(0);
        
        // Mock the scanner to simulate work and track concurrency
        doAnswer(invocation -> {
            Path filePath = invocation.getArgument(0);
            
            // Increment the concurrent thread counter
            int current = concurrentThreads.incrementAndGet();
            maxConcurrentThreads.updateAndGet(max -> Math.max(max, current));
            
            // Simulate some processing time (enough to ensure overlap if parallel)
            Thread.sleep(50);
            
            // Create a violation for this file
            SecurityViolation violation = new SecurityViolation(
                "TEST-" + filePath.getFileName(), 
                "Violation in " + filePath.getFileName(), 
                filePath, 1, "Code snippet", "MEDIUM", "Fix it", "example.com");
            
            // Decrement the concurrent thread counter
            concurrentThreads.decrementAndGet();
            
            // Count down the latch
            latch.countDown();
            
            return Collections.singletonList(violation);
        }).when(mockScanner).scanFile(any(Path.class));
        
        // Make sure all files can be processed by our mock scanner
        // First we clear the previous setup
        Mockito.reset(mockScanner);
        when(mockScanner.getSupportedFileExtensions()).thenReturn(Arrays.asList("cs", "config"));
        when(mockScanner.canProcessFile(any(Path.class))).thenReturn(true);
        
        // Register scanner and scan the directory
        engine.registerScanner(mockScanner);
        long startTime = System.currentTimeMillis();
        List<SecurityViolation> violations = engine.scanDirectory(tempDir);
        long endTime = System.currentTimeMillis();
        
        // Wait for all files to be processed
        assertTrue(latch.await(5, TimeUnit.SECONDS), "Timed out waiting for all files to be processed");
        
        // Verify results
        assertEquals(fileCount, violations.size());
        
        // If running in parallel, should have more than 1 concurrent thread at some point
        assertTrue(maxConcurrentThreads.get() > 1, "Files not processed in parallel (maxConcurrentThreads = " + maxConcurrentThreads.get() + ")");
        
        // Calculate and print the time saved compared to sequential processing
        long actualTime = endTime - startTime;
        long estimatedSequentialTime = fileCount * 50; // Each file takes about 50ms
        System.out.println("Parallel processing time: " + actualTime + "ms");
        System.out.println("Estimated sequential time: " + estimatedSequentialTime + "ms");
        System.out.println("Maximum concurrent threads: " + maxConcurrentThreads.get());
        
        // If truly parallel, should be significantly faster than sequential
        assertTrue(actualTime < estimatedSequentialTime * 0.9, 
            "Parallel processing not significantly faster than sequential processing");
    }
    
    @Test
    void testExportToJson(@TempDir Path tempDir) throws IOException {
        // Create a test violation with a string-based file path
        Path testFilePath = tempDir.resolve("test.cs");
        Files.writeString(testFilePath, "// Test file");
        
        SecurityViolation violation = new SecurityViolation(
            "TEST-001", "Test violation", testFilePath, 1, 
            "Code snippet", "HIGH", "Fix it", "https://example.com");
        
        List<SecurityViolation> violations = Collections.singletonList(violation);
        
        // Export to JSON
        Path outputPath = tempDir.resolve("results.json");
        engine.exportToJson(violations, outputPath);
        
        // Verify file was created and contains expected content
        assertTrue(Files.exists(outputPath));
        String content = Files.readString(outputPath);
        assertTrue(content.contains("TEST-001"));
        assertTrue(content.contains("Test violation"));
        assertTrue(content.contains("HIGH"));
        assertTrue(content.contains("Fix it"));
        assertTrue(content.contains("https://example.com"));
        assertTrue(content.contains("filePathString"));
    }
}