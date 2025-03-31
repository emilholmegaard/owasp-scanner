package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.SecurityRule;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Factory class for managing .NET security rules using Spring dependency
 * injection.
 * This class serves as a central point for accessing all .NET-specific security
 * rules
 * that are configured in the application context.
 * 
 * <p>
 * Rules are automatically injected by Spring based on the configuration in
 * {@code ScannerConfiguration}. Each rule is a Spring-managed bean that
 * implements
 * the {@link SecurityRule} interface.
 * </p>
 * 
 * <p>
 * Key features:
 * </p>
 * <ul>
 * <li>Automatic injection of .NET security rules</li>
 * <li>Centralized access to all .NET security rules</li>
 * <li>Spring component-based architecture</li>
 * </ul>
 *
 * @author Emil Holmegaard
 * @version 1.0
 * @see SecurityRule
 */
@Component
public class DotNetRuleFactory {

    private final List<SecurityRule> dotNetRules;

    /**
     * Constructs a new DotNetRuleFactory with the provided security rules.
     * Rules are automatically injected by Spring's dependency injection.
     *
     * @param dotNetRules List of .NET-specific security rules configured in the
     *                    application context
     */
    public DotNetRuleFactory(List<SecurityRule> dotNetRules) {
        this.dotNetRules = dotNetRules;
    }

    /**
     * Retrieves all configured .NET security rules.
     *
     * @return An unmodifiable list of all .NET security rules
     */
    public List<SecurityRule> getAllRules() {
        return dotNetRules;
    }
}