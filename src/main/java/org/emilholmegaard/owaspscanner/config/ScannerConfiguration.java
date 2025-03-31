package org.emilholmegaard.owaspscanner.config;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.ScannerEngine;
import org.emilholmegaard.owaspscanner.core.SecurityScanner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Spring configuration class for the OWASP Scanner.
 * Provides bean definitions for core scanner components.
 */
@Configuration
public class ScannerConfiguration {

    /**
     * Creates and configures the main scanner engine bean.
     * Automatically registers all available security scanners through dependency
     * injection.
     *
     * @param scanners List of security scanner implementations to be registered
     * @return Configured scanner engine instance
     */
    @Bean
    public ScannerEngine scannerEngine(List<SecurityScanner> scanners) {
        BaseScannerEngine engine = new BaseScannerEngine();
        // Automatically register all scanner beans
        scanners.forEach(engine::registerScanner);
        return engine;
    }
}
