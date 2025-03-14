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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

class BaseScannerEngineTest {
    
    private BaseScannerEngine engine;
    private SecurityScanner mockScanner;
    
    @BeforeEach
    void setUp() {
        engine = new BaseScannerEngine();
        mockScanner = Mockito.mock(SecurityScanner.class);
        
        // Setup mock scanner
        when(mockScanner.getSupportedFileExtensions()).thenReturn(Arrays.asList("cs", "config"));
        when(mockScanner.canProcessFile(Mockito.argThat(path -> 
            path.toString().endsWith(".cs") || path.toString().endsWith(".config")))).thenReturn(true);
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
        
        // Setup mock violation
        SecurityViolation mockViolation = new SecurityViolation.Builder(
            "TEST-001", "Test violation", testFile, 1)
            .build();
        
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
        SecurityViolation violation1 = new SecurityViolation.Builder(
            "TEST-001", "Violation in CS file", file1, 1).build();
        SecurityViolation violation2 = new SecurityViolation.Builder(
            "TEST-002", "Violation in config file", file2, 1).build();
        
        when(mockScanner.scanFile(file1)).thenReturn(Collections.singletonList(violation1));
        when(mockScanner.scanFile(file2)).thenReturn(Collections.singletonList(violation2));
        when(mockScanner.canProcessFile(file3)).thenReturn(false);
        
        // Register scanner and scan the directory
        engine.registerScanner(mockScanner);
        List<SecurityViolation> violations = engine.scanDirectory(tempDir);
        
        // Verify
        assertEquals(2, violations.size());
        assertTrue(violations.stream().anyMatch(v -> v.getRuleId().equals("TEST-001")));
        assertTrue(violations.stream().anyMatch(v -> v.getRuleId().equals("TEST-002")));
    }
    
    @Test
    void testExportToJson(@TempDir Path tempDir) throws IOException {
        // Create a test violation with a fixed path to avoid serialization issues
        SecurityViolation violation = new SecurityViolation.Builder(
            "TEST-001", "Test violation", Paths.get("test", "file.cs"), 1)
            .severity("HIGH")
            .remediation("Fix it")
            .reference("https://example.com")
            .build();
        
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
    }
}