package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.SecurityRule;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Factory class for creating and managing DotNet security rules.
 * Uses the factory pattern to instantiate appropriate rule objects.
 * Implements a HashMap-based approach for cleaner rule management.
 * Caches rule instances as singletons to improve performance.
 */
public class DotNetRuleFactory {
    
    // Singleton instance
    private static DotNetRuleFactory instance;
    
    // Map of rule ID to rule supplier for lazy instantiation
    private final Map<String, Supplier<SecurityRule>> ruleSuppliers;
    
    // Cache for rule instances to ensure singleton behavior for each rule
    private final Map<String, SecurityRule> ruleCache;
    
    /**
     * Private constructor to enforce singleton pattern.
     * Initializes the rule suppliers map and rule cache.
     */
    private DotNetRuleFactory() {
        ruleSuppliers = new HashMap<>();
        // Using ConcurrentHashMap for thread safety
        ruleCache = new ConcurrentHashMap<>();
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
     * Uses the rule cache to ensure each rule is a singleton.
     *
     * @return List of security rules for DotNet
     */
    public List<SecurityRule> createAllRules() {
        List<SecurityRule> rules = new ArrayList<>();
        
        // Get or create each rule instance
        for (Map.Entry<String, Supplier<SecurityRule>> entry : ruleSuppliers.entrySet()) {
            String ruleId = entry.getKey();
            SecurityRule rule = getRuleFromCache(ruleId);
            rules.add(rule);
        }
        
        return rules;
    }
    
    /**
     * Creates a specific rule by ID.
     * Uses the rule cache to ensure each rule is a singleton.
     *
     * @param ruleId The ID of the rule to create
     * @return The requested security rule, or null if not found
     */
    public SecurityRule createRule(String ruleId) {
        if (!ruleSuppliers.containsKey(ruleId)) {
            return null;
        }
        return getRuleFromCache(ruleId);
    }
    
    /**
     * Gets a rule from the cache or creates it if it doesn't exist.
     *
     * @param ruleId The ID of the rule to get or create
     * @return The cached or newly created rule instance
     */
    private SecurityRule getRuleFromCache(String ruleId) {
        // Using computeIfAbsent for thread-safe lazy initialization
        return ruleCache.computeIfAbsent(ruleId, id -> {
            Supplier<SecurityRule> supplier = ruleSuppliers.get(id);
            return supplier.get();
        });
    }
    
    /**
     * Registers a new rule supplier with the factory.
     * 
     * @param ruleId The ID of the rule
     * @param supplier The supplier function to create the rule
     */
    public void registerRule(String ruleId, Supplier<SecurityRule> supplier) {
        ruleSuppliers.put(ruleId, supplier);
        // Remove from cache if it exists to ensure new supplier is used next time
        ruleCache.remove(ruleId);
    }
    
    /**
     * Clears the rule cache.
     * This can be useful in testing or when rules need to be recreated.
     */
    public void clearCache() {
        ruleCache.clear();
    }
}