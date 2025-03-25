package org.emilholmegaard.owaspscanner.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the ScannerConfig class.
 */
public class ScannerConfigTest {

    @Test
    public void testDefaultConfig() {
        ScannerConfig config = ScannerConfig.defaultConfig();
        
        assertTrue(config.isParallelProcessing(), "Default config should have parallel processing enabled");
        assertEquals(Runtime.getRuntime().availableProcessors(), config.getMaxThreads(), 
                "Default config should use available processors for thread count");
        assertTrue(config.isCacheFileContent(), "Default config should have file caching enabled");
        assertEquals(5000, config.getMaxLineLengthBytes(), "Default config should have 5000 bytes max line length");
        assertTrue(config.isEarlyTermination(), "Default config should have early termination enabled");
        assertEquals(100, config.getMaxViolationsPerFile(), "Default config should allow 100 violations per file");
        assertEquals(10 * 1024 * 1024, config.getMaxFileSizeBytes(), "Default config should have 10MB max file size");
    }
    
    @Test
    public void testFastConfig() {
        ScannerConfig config = ScannerConfig.fastConfig();
        
        assertTrue(config.isParallelProcessing(), "Fast config should have parallel processing enabled");
        assertEquals(Runtime.getRuntime().availableProcessors() * 2, config.getMaxThreads(),
                "Fast config should use twice the available processors for thread count");
        assertTrue(config.isCacheFileContent(), "Fast config should have file caching enabled");
        assertTrue(config.isEarlyTermination(), "Fast config should have early termination enabled");
        assertEquals(10, config.getMaxViolationsPerFile(), "Fast config should allow 10 violations per file");
    }
    
    @Test
    public void testThoroughConfig() {
        ScannerConfig config = ScannerConfig.thoroughConfig();
        
        assertTrue(config.isParallelProcessing(), "Thorough config should have parallel processing enabled");
        assertTrue(config.isCacheFileContent(), "Thorough config should have file caching enabled");
        assertFalse(config.isEarlyTermination(), "Thorough config should have early termination disabled");
        assertEquals(Integer.MAX_VALUE, config.getMaxViolationsPerFile(), 
                "Thorough config should allow maximum violations per file");
    }
    
    @Test
    public void testFluentApiChaining() {
        ScannerConfig config = new ScannerConfig()
                .setParallelProcessing(false)
                .setMaxThreads(4)
                .setCacheFileContent(false)
                .setMaxLineLengthBytes(1000)
                .setEarlyTermination(false)
                .setMaxViolationsPerFile(5)
                .setMaxFileSizeBytes(5 * 1024 * 1024);
                
        assertFalse(config.isParallelProcessing(), "Fluent API should set parallel processing");
        assertEquals(4, config.getMaxThreads(), "Fluent API should set thread count");
        assertFalse(config.isCacheFileContent(), "Fluent API should set file caching");
        assertEquals(1000, config.getMaxLineLengthBytes(), "Fluent API should set max line length");
        assertFalse(config.isEarlyTermination(), "Fluent API should set early termination");
        assertEquals(5, config.getMaxViolationsPerFile(), "Fluent API should set max violations per file");
        assertEquals(5 * 1024 * 1024, config.getMaxFileSizeBytes(), "Fluent API should set max file size");
    }
    
    @Test
    public void testInvalidValues() {
        ScannerConfig config = new ScannerConfig();
        
        config.setMaxThreads(-1);
        assertTrue(config.getMaxThreads() > 0, "Max threads should not allow negative values");
        
        config.setMaxLineLengthBytes(0);
        assertTrue(config.getMaxLineLengthBytes() > 0, "Max line length should not allow zero");
        
        config.setMaxViolationsPerFile(-10);
        assertTrue(config.getMaxViolationsPerFile() > 0, "Max violations should not allow negative values");
        
        config.setMaxFileSizeBytes(-1024);
        assertTrue(config.getMaxFileSizeBytes() > 0, "Max file size should not allow negative values");
    }
}
