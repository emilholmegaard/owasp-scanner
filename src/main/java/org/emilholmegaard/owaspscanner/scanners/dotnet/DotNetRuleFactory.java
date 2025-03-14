package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.SecurityRule;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Factory class for creating and managing DotNet security rules.
 * Uses the factory pattern to instantiate appropriate rule objects.
 */
public class DotNetRuleFactory {
    
    private static DotNetRuleFactory instance;
    
    private DotNetRuleFactory() {
        // Private constructor to enforce singleton pattern
    }
    
    /**
     * Gets the singleton instance of the factory.
     *
     * @return The DotNetRuleFactory instance
     */
    public static synchronized DotNetRuleFactory getInstance() {
        if (instance == null) {
            instance = new DotNetRuleFactory();
        }
        return instance;
    }
    
    /**
     * Creates all available DotNet security rules.
     *
     * @return List of security rules for DotNet
     */
    public List<SecurityRule> createAllRules() {
        List<SecurityRule> rules = new ArrayList<>();
        
        // Add each rule to the list
        rules.add(new HttpSecurityHeadersRule());
        rules.add(new InputValidationRule());
        rules.add(new SqlInjectionRule());
        rules.add(new XssPreventionRule());
        rules.add(new CsrfProtectionRule());
        rules.add(new SecureConfigurationRule());
        rules.add(new AuthenticationRule());
        rules.add(new SessionManagementRule());
        rules.add(new ExceptionHandlingRule());
        
        return rules;
    }
    
    /**
     * Creates a specific rule by ID.
     *
     * @param ruleId The ID of the rule to create
     * @return The requested security rule, or null if not found
     */
    public SecurityRule createRule(String ruleId) {
        switch (ruleId) {
            case "DOTNET-SEC-001":
                return new HttpSecurityHeadersRule();
            case "DOTNET-SEC-002":
                return new InputValidationRule();
            case "DOTNET-SEC-003":
                return new SqlInjectionRule();
            case "DOTNET-SEC-004":
                return new XssPreventionRule();
            case "DOTNET-SEC-005":
                return new CsrfProtectionRule();
            case "DOTNET-SEC-006":
                return new SecureConfigurationRule();
            case "DOTNET-SEC-007":
                return new AuthenticationRule();
            case "DOTNET-SEC-008":
                return new SessionManagementRule();
            case "DOTNET-SEC-009":
                return new ExceptionHandlingRule();
            default:
                return null;
        }
    }
}
