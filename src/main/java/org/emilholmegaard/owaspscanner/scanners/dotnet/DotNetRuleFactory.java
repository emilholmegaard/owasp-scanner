package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.SecurityRule;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Factory class for creating and managing DotNet security rules.
 * Uses the factory pattern to instantiate appropriate rule objects.
 * Implements a HashMap-based approach for cleaner rule management.
 */
public class DotNetRuleFactory {
    
    // Singleton instance
    private static DotNetRuleFactory instance;
    
    // Map of rule ID to rule supplier for lazy instantiation
    private final Map<String, Supplier<SecurityRule>> ruleSuppliers;
    
    /**
     * Private constructor to enforce singleton pattern.
     * Initializes the rule suppliers map.
     */
    private DotNetRuleFactory() {
        ruleSuppliers = new HashMap<>();
        registerRules();
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
     * Registers all available rules with their suppliers.
     */
    private void registerRules() {
        ruleSuppliers.put("DOTNET-SEC-001", HttpSecurityHeadersRule::new);
        ruleSuppliers.put("DOTNET-SEC-002", InputValidationRule::new);
        ruleSuppliers.put("DOTNET-SEC-003", SqlInjectionRule::new);
        ruleSuppliers.put("DOTNET-SEC-004", XssPreventionRule::new);
        ruleSuppliers.put("DOTNET-SEC-005", CsrfProtectionRule::new);
        ruleSuppliers.put("DOTNET-SEC-006", SecureConfigurationRule::new);
        ruleSuppliers.put("DOTNET-SEC-007", AuthenticationRule::new);
        ruleSuppliers.put("DOTNET-SEC-008", SessionManagementRule::new);
        ruleSuppliers.put("DOTNET-SEC-009", ExceptionHandlingRule::new);
    }
    
    /**
     * Creates all available DotNet security rules.
     *
     * @return List of security rules for DotNet
     */
    public List<SecurityRule> createAllRules() {
        List<SecurityRule> rules = new ArrayList<>();
        
        // Create each rule using its supplier
        for (Supplier<SecurityRule> supplier : ruleSuppliers.values()) {
            rules.add(supplier.get());
        }
        
        return rules;
    }
    
    /**
     * Creates a specific rule by ID.
     *
     * @param ruleId The ID of the rule to create
     * @return The requested security rule, or null if not found
     */
    public SecurityRule createRule(String ruleId) {
        Supplier<SecurityRule> supplier = ruleSuppliers.get(ruleId);
        return (supplier != null) ? supplier.get() : null;
    }
    
    /**
     * Registers a new rule supplier with the factory.
     * 
     * @param ruleId The ID of the rule
     * @param supplier The supplier function to create the rule
     */
    public void registerRule(String ruleId, Supplier<SecurityRule> supplier) {
        ruleSuppliers.put(ruleId, supplier);
    }
}
