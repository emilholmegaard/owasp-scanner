package org.emilholmegaard.owaspscanner;

import org.emilholmegaard.owaspscanner.core.ScannerConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the OwaspScannerApp class focusing on configuration options.
 */
public class OwaspScannerAppTest {

    private ByteArrayOutputStream outputStream;
    private PrintStream originalOut;
    
    @BeforeEach
    public void setUp() {
        // Capture stdout for verifying output
        originalOut = System.out;
        outputStream = new ByteArrayOutputStream();
        System.setOut(new PrintStream(outputStream));
    }
    
    @Test
    public void testDefaultConfiguration() throws Exception {
        // Access the private parseScannerConfig method via reflection
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{"scan", "some/directory"};
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertTrue(config.isParallelProcessing(), "Default config should enable parallel processing");
        assertEquals(Runtime.getRuntime().availableProcessors(), config.getMaxThreads());
        assertTrue(config.isCacheFileContent(), "Default config should enable file content caching");
        assertTrue(config.isEarlyTermination(), "Default config should enable early termination");
        assertEquals(100, config.getMaxViolationsPerFile());
        assertEquals(10 * 1024 * 1024, config.getMaxFileSizeBytes());
        
        String output = outputStream.toString();
        assertTrue(output.contains("Using default scan configuration"), 
                "Output should indicate default configuration is used");
    }
    
    @Test
    public void testFastConfiguration() throws Exception {
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{"scan", "some/directory", "--fast"};
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertTrue(config.isParallelProcessing(), "Fast config should enable parallel processing");
        assertEquals(Runtime.getRuntime().availableProcessors() * 2, config.getMaxThreads(),
                "Fast config should use twice the available processors");
        assertTrue(config.isCacheFileContent(), "Fast config should enable file content caching");
        assertTrue(config.isEarlyTermination(), "Fast config should enable early termination");
        assertEquals(10, config.getMaxViolationsPerFile(), "Fast config should limit violations per file");
        
        String output = outputStream.toString();
        assertTrue(output.contains("Using fast scan configuration"), 
                "Output should indicate fast configuration is used");
    }
    
    @Test
    public void testThoroughConfiguration() throws Exception {
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{"scan", "some/directory", "--thorough"};
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertTrue(config.isParallelProcessing(), "Thorough config should enable parallel processing");
        assertTrue(config.isCacheFileContent(), "Thorough config should enable file content caching");
        assertFalse(config.isEarlyTermination(), "Thorough config should disable early termination");
        assertEquals(Integer.MAX_VALUE, config.getMaxViolationsPerFile(), 
                "Thorough config should not limit violations per file");
        
        String output = outputStream.toString();
        assertTrue(output.contains("Using thorough scan configuration"), 
                "Output should indicate thorough configuration is used");
    }
    
    @Test
    public void testCustomThreadConfiguration() throws Exception {
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{"scan", "some/directory", "--threads=4"};
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertEquals(4, config.getMaxThreads(), "Config should use specified thread count");
        
        String output = outputStream.toString();
        assertTrue(output.contains("Using 4 threads for scanning"), 
                "Output should indicate custom thread configuration");
    }
    
    @Test
    public void testMaxFileSizeConfiguration() throws Exception {
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{"scan", "some/directory", "--max-file-size=5"};
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertEquals(5 * 1024 * 1024, config.getMaxFileSizeBytes(), 
                "Config should use specified max file size");
        
        String output = outputStream.toString();
        assertTrue(output.contains("Maximum file size set to 5MB"), 
                "Output should indicate custom file size configuration");
    }
    
    @Test
    public void testMaxViolationsConfiguration() throws Exception {
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{"scan", "some/directory", "--max-violations=50"};
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertEquals(50, config.getMaxViolationsPerFile(), 
                "Config should use specified max violations per file");
        
        String output = outputStream.toString();
        assertTrue(output.contains("Maximum violations per file set to 50"), 
                "Output should indicate custom violations configuration");
    }
    
    @Test
    public void testDisableOptions() throws Exception {
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{
            "scan", "some/directory", 
            "--no-cache", "--no-parallel", "--no-early-termination"
        };
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertFalse(config.isCacheFileContent(), "Config should disable file content caching");
        assertFalse(config.isParallelProcessing(), "Config should disable parallel processing");
        assertFalse(config.isEarlyTermination(), "Config should disable early termination");
        
        String output = outputStream.toString();
        assertTrue(output.contains("File content caching disabled"), 
                "Output should indicate caching is disabled");
        assertTrue(output.contains("Parallel processing disabled"), 
                "Output should indicate parallel processing is disabled");
        assertTrue(output.contains("Early termination disabled"), 
                "Output should indicate early termination is disabled");
    }
    
    @Test
    public void testCombinedOptions() throws Exception {
        Method parseConfigMethod = OwaspScannerApp.class.getDeclaredMethod("parseScannerConfig", String[].class);
        parseConfigMethod.setAccessible(true);
        
        String[] args = new String[]{
            "scan", "some/directory", 
            "--fast", "--threads=8", "--max-file-size=2", "--no-early-termination"
        };
        ScannerConfig config = (ScannerConfig) parseConfigMethod.invoke(null, (Object) args);
        
        assertTrue(config.isParallelProcessing(), "Config should enable parallel processing (from fast)");
        assertEquals(8, config.getMaxThreads(), 
                "Config should use explicitly specified thread count (overriding fast)");
        assertEquals(2 * 1024 * 1024, config.getMaxFileSizeBytes(), 
                "Config should use specified max file size");
        assertFalse(config.isEarlyTermination(), 
                "Config should use explicitly disabled early termination (overriding fast)");
        assertEquals(10, config.getMaxViolationsPerFile(), 
                "Config should use max violations from fast preset");
    }
}
