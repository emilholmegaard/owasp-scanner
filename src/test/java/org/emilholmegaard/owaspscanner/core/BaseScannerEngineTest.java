package org.emilholmegaard.owaspscanner.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the BaseScannerEngine class focusing on configuration usage.
 */
public class BaseScannerEngineTest {

    @TempDir
    Path tempDir;
    
    @Mock
    SecurityScanner mockScanner;
    
    private BaseScannerEngine engine;
    private Path testFile;
    
    @BeforeEach
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);
        
        // Create test engine
        engine = new BaseScannerEngine();
        
        // Create a test file
        testFile = tempDir.resolve("test.txt");
        List<String> lines = Arrays.asList(
            "First line of test file",
            "Second line of test file",
            "Third line of test file",
            "Fourth line of test file",
            "Fifth line of test file"
        );
        Files.write(testFile, lines, StandardCharsets.UTF_8);
        
        // Mock scanner behavior
        when(mockScanner.getName()).thenReturn("TestScanner");
        when(mockScanner.getTechnology()).thenReturn("Test");
        when(mockScanner.getSupportedFileExtensions()).thenReturn(Arrays.asList("txt"));
        when(mockScanner.canProcessFile(any(Path.class))).thenReturn(true);
        
        // Register the mock scanner
        engine.registerScanner(mockScanner);
    }
    
    @Test
    public void testSetAndGetConfig() {
        // Default config should be used initially
        ScannerConfig defaultConfig = engine.getConfig();
        assertTrue(defaultConfig.isParallelProcessing());
        
        // Create a custom config
        ScannerConfig customConfig = new ScannerConfig()
            .setParallelProcessing(false)
            .setMaxThreads(2)
            .setCacheFileContent(false);
            
        // Set the custom config
        engine.setConfig(customConfig);
        
        // Verify the config was set
        ScannerConfig retrievedConfig = engine.getConfig();
        assertFalse(retrievedConfig.isParallelProcessing());
        assertEquals(2, retrievedConfig.getMaxThreads());
        assertFalse(retrievedConfig.isCacheFileContent());
    }
    
    @Test
    public void testEarlyTerminationConfig() throws IOException {
        // Setup mock scanner to return multiple violations
        List<SecurityViolation> mockViolations = Arrays.asList(
            new SecurityViolation("RULE1", "Violation 1", "HIGH", testFile, 1),
            new SecurityViolation("RULE2", "Violation 2", "MEDIUM", testFile, 2),
            new SecurityViolation("RULE3", "Violation 3", "LOW", testFile, 3),
            new SecurityViolation("RULE4", "Violation 4", "MEDIUM", testFile, 4),
            new SecurityViolation("RULE5", "Violation 5", "HIGH", testFile, 5)
        );
        when(mockScanner.scanFile(any(Path.class))).thenReturn(mockViolations);
        
        // Set config to limit violations per file
        ScannerConfig config = new ScannerConfig()
            .setEarlyTermination(true)
            .setMaxViolationsPerFile(3);
        engine.setConfig(config);
        
        // Scan the file
        List<SecurityViolation> result = engine.scanFile(testFile);
        
        // Verify that only maxViolationsPerFile violations were returned
        assertEquals(3, result.size(), "Engine should limit violations based on config");
    }
    
    @Test
    public void testNoEarlyTerminationConfig() throws IOException {
        // Setup mock scanner to return multiple violations
        List<SecurityViolation> mockViolations = Arrays.asList(
            new SecurityViolation("RULE1", "Violation 1", "HIGH", testFile, 1),
            new SecurityViolation("RULE2", "Violation 2", "MEDIUM", testFile, 2),
            new SecurityViolation("RULE3", "Violation 3", "LOW", testFile, 3),
            new SecurityViolation("RULE4", "Violation 4", "MEDIUM", testFile, 4),
            new SecurityViolation("RULE5", "Violation 5", "HIGH", testFile, 5)
        );
        when(mockScanner.scanFile(any(Path.class))).thenReturn(mockViolations);
        
        // Set config to disable early termination
        ScannerConfig config = new ScannerConfig()
            .setEarlyTermination(false)
            .setMaxViolationsPerFile(3);
        engine.setConfig(config);
        
        // Scan the file
        List<SecurityViolation> result = engine.scanFile(testFile);
        
        // Verify that maxViolationsPerFile is still applied for result limiting
        assertEquals(3, result.size(), "Engine should limit violations based on config");
    }
    
    @Test
    public void testFileSizeLimitConfig() throws IOException {
        // Create a "large" test file
        Path largeFile = tempDir.resolve("large.txt");
        StringBuilder content = new StringBuilder();
        for (int i = 0; i < 1000; i++) {
            content.append("Line ").append(i).append(" of large test file\n");
        }
        Files.writeString(largeFile, content.toString(), StandardCharsets.UTF_8);
        
        // Set config with small file size limit
        long fileSize = Files.size(largeFile);
        ScannerConfig config = new ScannerConfig()
            .setMaxFileSizeBytes(fileSize - 1); // Set limit below actual size
        engine.setConfig(config);
        
        // Create a temporary directory with the test file
        Path tempTestDir = tempDir.resolve("testdir");
        Files.createDirectory(tempTestDir);
        Path fileInDir = tempTestDir.resolve("test.txt");
        Files.copy(testFile, fileInDir);
        
        // Scan the directory (with both files)
        Path largeFileInDir = tempTestDir.resolve("large.txt");
        Files.copy(largeFile, largeFileInDir);
        
        // Scan the directory
        List<SecurityViolation> results = engine.scanDirectory(tempTestDir);
        
        // Verify that only small file is processed
        verify(mockScanner, times(1)).scanFile(eq(fileInDir));
        verify(mockScanner, never()).scanFile(eq(largeFileInDir));
    }
    
    @Test
    public void testLineLengthLimitConfig() throws IOException {
        // Create a file with a very long line
        Path fileWithLongLine = tempDir.resolve("longline.txt");
        StringBuilder longLine = new StringBuilder("Line with ");
        for (int i = 0; i < 10000; i++) {
            longLine.append("very ");
        }
        longLine.append("long text");
        
        List<String> lines = Arrays.asList(
            "Normal line 1",
            longLine.toString(),
            "Normal line 2"
        );
        Files.write(fileWithLongLine, lines, StandardCharsets.UTF_8);
        
        // Set max line length in config
        ScannerConfig config = new ScannerConfig()
            .setMaxLineLengthBytes(50);
        engine.setConfig(config);
        
        // Read the file using engine's readFileWithFallback method
        List<String> readLines = engine.readFileWithFallback(fileWithLongLine);
        
        // Check that the long line was truncated
        assertTrue(readLines.get(1).length() <= 65, 
            "Long line should be truncated (including truncation message)");
        assertTrue(readLines.get(1).endsWith("... [truncated]"), 
            "Truncated line should have truncation indicator");
    }
    
    @Test
    public void testFileCachingConfig() throws IOException {
        // Set config to enable caching
        ScannerConfig cachingConfig = new ScannerConfig()
            .setCacheFileContent(true);
        engine.setConfig(cachingConfig);
        
        // Read the file multiple times
        List<String> firstRead = engine.readFileWithFallback(testFile);
        List<String> secondRead = engine.readFileWithFallback(testFile);
        
        // Modify the file
        Files.writeString(testFile, "Modified content", StandardCharsets.UTF_8);
        
        // Read again
        List<String> thirdRead = engine.readFileWithFallback(testFile);
        
        // Check that the second read was from cache (same object)
        assertSame(firstRead, secondRead, "Second read should be the same object (from cache)");
        
        // Check that third read has updated content (after file modified)
        assertNotSame(secondRead, thirdRead, "Third read should be a different object (after modification)");
        assertEquals("Modified content", thirdRead.get(0), "Third read should have modified content");
        
        // Now disable caching
        ScannerConfig noCachingConfig = new ScannerConfig()
            .setCacheFileContent(false);
        engine.setConfig(noCachingConfig);
        
        // Modify file again
        Files.writeString(testFile, "Modified again", StandardCharsets.UTF_8);
        
        // Read again
        List<String> fourthRead = engine.readFileWithFallback(testFile);
        List<String> fifthRead = engine.readFileWithFallback(testFile);
        
        // Verify that caching is disabled (different objects)
        assertNotSame(fourthRead, fifthRead, "Reads with caching disabled should be different objects");
    }
}
