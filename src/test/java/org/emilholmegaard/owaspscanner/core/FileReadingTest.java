package org.emilholmegaard.owaspscanner.core;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test cases for the optimized file reading mechanism in BaseScannerEngine.
 */
class FileReadingTest {
    
    @TempDir
    Path tempDir;
    
    private Path utf8File;
    private Path windows1252File;
    private Path longLineFile;
    
    @BeforeEach
    void setUp() throws IOException {
        // Create test files with different encodings
        utf8File = tempDir.resolve("utf8_content.txt");
        windows1252File = tempDir.resolve("windows1252_content.txt");
        longLineFile = tempDir.resolve("long_line.txt");
        
        // Create UTF-8 file
        String utf8Content = "Hello, this is UTF-8 text with special characters: ö ä ü ß 日本語 😊";
        Files.write(utf8File, utf8Content.getBytes(StandardCharsets.UTF_8));
        
        // Create Windows-1252 file
        String windows1252Content = "This is Windows-1252 content with special characters: € â ê î ô û";
        Files.write(windows1252File, windows1252Content.getBytes("windows-1252"));
        
        // Create a file with a very long line
        StringBuilder longLine = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            longLine.append("X");
        }
        Files.write(longLineFile, longLine.toString().getBytes(StandardCharsets.UTF_8));
    }
    
    @Test
    void testReadingUtf8File() {
        List<String> lines = BaseScannerEngine.readFileWithFallback(utf8File);
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).contains("UTF-8 text"), "Should correctly read UTF-8 content");
        assertTrue(lines.get(0).contains("日本語"), "Should correctly read UTF-8 special characters");
    }
    
    @Test
    void testReadingWindows1252File() {
        List<String> lines = BaseScannerEngine.readFileWithFallback(windows1252File);
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).contains("Windows-1252 content"), "Should correctly read Windows-1252 content");
        assertTrue(lines.get(0).contains("€"), "Should correctly read Windows-1252 special characters");
    }
    
    @Test
    void testLineLengthLimiting() {
        List<String> lines = BaseScannerEngine.readFileWithFallback(longLineFile);
        assertEquals(1, lines.size());
        assertTrue(lines.get(0).endsWith("... [truncated]"), "Long line should be truncated");
        assertTrue(lines.get(0).length() < 10000, "Long line should be truncated to shorter length");
    }
    
    @Test
    void testCaching() throws IOException {
        // First read should populate the cache
        List<String> firstRead = BaseScannerEngine.readFileWithFallback(utf8File);
        
        // Modify the file - this should not affect the second read if caching works
        String modifiedContent = "Modified content that shouldn't be read due to caching";
        Files.write(utf8File, modifiedContent.getBytes(StandardCharsets.UTF_8));
        
        // Second read should return the cached content
        List<String> secondRead = BaseScannerEngine.readFileWithFallback(utf8File);
        
        // Should return the same content from cache
        assertEquals(firstRead, secondRead, "Second read should return cached content");
        assertFalse(secondRead.get(0).contains("Modified content"), 
            "Cache should prevent reading modified file content");
        
        // Update the file modification time to force a cache refresh
        Files.setLastModifiedTime(utf8File, FileTime.from(Instant.now().plusSeconds(10)));
        
        // After modification time change, content should be re-read
        List<String> thirdRead = BaseScannerEngine.readFileWithFallback(utf8File);
        assertTrue(thirdRead.get(0).contains("Modified content"), 
            "File should be re-read after modification time change");
    }
    
    @Test
    void testClearingCache() throws IOException {
        // First read populates cache
        BaseScannerEngine.readFileWithFallback(utf8File);
        
        // Modify the file
        String modifiedContent = "Modified content after clearing cache";
        Files.write(utf8File, modifiedContent.getBytes(StandardCharsets.UTF_8));
        
        // Clear the cache
        BaseScannerEngine.clearFileContentCache();
        
        // Read again - should get the modified content
        List<String> lines = BaseScannerEngine.readFileWithFallback(utf8File);
        assertTrue(lines.get(0).contains("Modified content"), 
            "File should be re-read after clearing cache");
    }
    
    @Test
    void testConcurrentReads() throws InterruptedException {
        int threadCount = 10;
        CountDownLatch latch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        
        // Create multiple files
        List<Path> testFiles = IntStream.range(0, 5)
            .mapToObj(i -> {
                try {
                    Path file = tempDir.resolve("concurrent_test_" + i + ".txt");
                    Files.write(file, ("Concurrent test file " + i).getBytes(StandardCharsets.UTF_8));
                    return file;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            })
            .collect(Collectors.toList());
        
        // Read the files concurrently
        for (int i = 0; i < threadCount; i++) {
            int threadIndex = i;
            executor.submit(() -> {
                try {
                    // Each thread reads all files
                    for (Path file : testFiles) {
                        List<String> lines = BaseScannerEngine.readFileWithFallback(file);
                        assertFalse(lines.isEmpty(), "Thread " + threadIndex + " should read file content");
                    }
                } finally {
                    latch.countDown();
                }
            });
        }
        
        // Wait for all threads to complete
        assertTrue(latch.await(5, TimeUnit.SECONDS), "All threads should complete within timeout");
        executor.shutdown();
        
        // Additional verification
        for (Path file : testFiles) {
            List<String> lines = BaseScannerEngine.readFileWithFallback(file);
            assertNotNull(lines, "File content should be cached and readable");
        }
    }
    
    @Test
    void testBinaryFallback() throws IOException {
        // Create a file with binary content
        Path binaryFile = tempDir.resolve("binary_file.bin");
        byte[] binaryData = new byte[100];
        for (int i = 0; i < binaryData.length; i++) {
            binaryData[i] = (byte) i;
        }
        Files.write(binaryFile, binaryData);
        
        // Should be able to read using binary fallback
        List<String> lines = BaseScannerEngine.readFileWithFallback(binaryFile);
        assertNotNull(lines, "Binary fallback should not return null");
        assertFalse(lines.isEmpty(), "Binary fallback should return some content");
    }
    
    @Test
    void testPerformanceImprovement() throws IOException {
        // Create a reasonably sized file
        Path testFile = tempDir.resolve("performance_test.txt");
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            content.append("Line ").append(i).append(" with some content to make it realistic\n");
        }
        Files.write(testFile, content.toString().getBytes(StandardCharsets.UTF_8));
        
        // First read - will use normal reading and caching
        long startFirstRead = System.nanoTime();
        List<String> firstReadLines = BaseScannerEngine.readFileWithFallback(testFile);
        long firstReadTime = System.nanoTime() - startFirstRead;
        
        // Second read - should use cache
        long startSecondRead = System.nanoTime();
        List<String> secondReadLines = BaseScannerEngine.readFileWithFallback(testFile);
        long secondReadTime = System.nanoTime() - startSecondRead;
        
        // Verify content is the same
        assertEquals(firstReadLines, secondReadLines, "Both reads should return the same content");
        
        // Output timing information for diagnostics
        System.out.println("First read (normal): " + TimeUnit.NANOSECONDS.toMillis(firstReadTime) + "ms");
        System.out.println("Second read (cached): " + TimeUnit.NANOSECONDS.toMillis(secondReadTime) + "ms");
        
        // Verify performance improvement with caching
        assertTrue(secondReadTime < firstReadTime, "Cached read should be faster than normal read");
    }
    
    @Test
    void testMultipleReadsOfSameFile() throws IOException {
        // Create test file
        Path testFile = tempDir.resolve("repeated_reads.txt");
        Files.write(testFile, "Content for repeated reads test".getBytes(StandardCharsets.UTF_8));
        
        // Read multiple times to ensure cache works consistently
        List<String> result1 = BaseScannerEngine.readFileWithFallback(testFile);
        List<String> result2 = BaseScannerEngine.readFileWithFallback(testFile);
        List<String> result3 = BaseScannerEngine.readFileWithFallback(testFile);
        
        // All results should be the same
        assertEquals(result1, result2, "Repeated reads should return same content");
        assertEquals(result2, result3, "Repeated reads should return same content");
        
        // Verify cache works by modifying file without changing timestamp
        Files.write(testFile, "Modified content without timestamp change".getBytes(StandardCharsets.UTF_8));
        List<String> result4 = BaseScannerEngine.readFileWithFallback(testFile);
        
        // Should still get cached content
        assertEquals(result1, result4, "Should return cached content without checking file");
    }
}