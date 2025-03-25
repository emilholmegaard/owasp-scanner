package org.emilholmegaard.owaspscanner.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the BaseScannerEngine configuration features.
 */
public class BaseScannerEngineConfigTest {

    @TempDir
    Path tempDir;
    
    private BaseScannerEngine engine;
    private Path testFile;
    private String testContent = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5";
    
    @BeforeEach
    public void setUp() throws IOException {
        // Create test engine
        engine = new BaseScannerEngine();
        
        // Create a test file
        testFile = tempDir.resolve("test.txt");
        Files.writeString(testFile, testContent, StandardCharsets.UTF_8);
    }
    
    @Test
    public void testDefaultConfig() {
        // Default config should be set automatically
        ScannerConfig config = engine.getConfig();
        assertNotNull(config, "Default config should be created");
        
        // Verify default values
        assertTrue(config.isParallelProcessing(), "Default config should enable parallel processing");
        assertEquals(Runtime.getRuntime().availableProcessors(), config.getMaxThreads());
        assertTrue(config.isCacheFileContent(), "Default config should enable file caching");
    }
    
    @Test
    public void testSetConfig() {
        // Create a custom config
        ScannerConfig customConfig = new ScannerConfig()
            .setParallelProcessing(false)
            .setMaxThreads(3)
            .setCacheFileContent(false)
            .setMaxLineLengthBytes(100)
            .setMaxViolationsPerFile(10);
            
        // Set the config
        engine.setConfig(customConfig);
        
        // Verify that the config was set
        ScannerConfig retrievedConfig = engine.getConfig();
        assertSame(customConfig, retrievedConfig, "Config reference should be the same");
        assertFalse(retrievedConfig.isParallelProcessing());
        assertEquals(3, retrievedConfig.getMaxThreads());
        assertFalse(retrievedConfig.isCacheFileContent());
        assertEquals(100, retrievedConfig.getMaxLineLengthBytes());
        assertEquals(10, retrievedConfig.getMaxViolationsPerFile());
    }
    
    @Test
    public void testReadFileWithCaching() throws IOException {
        // Enable file content caching
        ScannerConfig config = new ScannerConfig().setCacheFileContent(true);
        engine.setConfig(config);
        
        // First read
        List<String> lines1 = engine.readFileWithFallback(testFile);
        assertNotNull(lines1);
        assertEquals(5, lines1.size());
        
        // Second read should use cache (same object reference)
        List<String> lines2 = engine.readFileWithFallback(testFile);
        assertSame(lines1, lines2, "Cache should return same object reference");
        
        // Modify the file
        Files.writeString(testFile, testContent + "\nLine 6", StandardCharsets.UTF_8);
        
        // Third read should get new content (different object)
        List<String> lines3 = engine.readFileWithFallback(testFile);
        assertNotSame(lines2, lines3, "Should return new object after file modified");
        assertEquals(6, lines3.size(), "Should have added line");
    }
    
    @Test
    public void testReadFileWithoutCaching() throws IOException {
        // Disable file content caching
        ScannerConfig config = new ScannerConfig().setCacheFileContent(false);
        engine.setConfig(config);
        
        // First read
        List<String> lines1 = engine.readFileWithFallback(testFile);
        assertNotNull(lines1);
        assertEquals(5, lines1.size());
        
        // Second read should not use cache (different object reference)
        List<String> lines2 = engine.readFileWithFallback(testFile);
        assertNotSame(lines1, lines2, "Should not use cache when disabled");
        assertEquals(5, lines2.size());
    }
    
    @Test
    public void testLineLengthLimiting() throws IOException {
        // Set a small line length limit
        ScannerConfig config = new ScannerConfig()
            .setMaxLineLengthBytes(4) // Only 4 chars
            .setCacheFileContent(false);
        engine.setConfig(config);
        
        // Read the file
        List<String> lines = engine.readFileWithFallback(testFile);
        
        // Verify that lines are truncated
        assertEquals("Line... [truncated]", lines.get(0));
        assertEquals("Line... [truncated]", lines.get(1));
    }
    
    @Test
    public void testCreateDefaultRuleContext() {
        // Create a context
        RuleContext context = engine.new DefaultRuleContext(testFile);
        
        // Verify the context
        assertEquals(testFile, context.getFilePath());
        List<String> content = context.getFileContent();
        assertNotNull(content);
        assertEquals(5, content.size());
        assertEquals("Line 1", content.get(0));
    }
}
