package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.SecurityRule;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

public class DotNetRuleFactoryTest {

    @Test
    public void testCreateAllRules() {
        // Get the factory instance
        DotNetRuleFactory factory = DotNetRuleFactory.getInstance();
        
        // Get all rules
        List<SecurityRule> rules = factory.createAllRules();
        
        // Verify that all expected rules are created
        assertEquals(9, rules.size(), "Should create 9 rules");
        
        // Verify that we have one of each type of rule
        assertTrue(rules.stream().anyMatch(r -> r instanceof HttpSecurityHeadersRule),
            "Should contain HttpSecurityHeadersRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof InputValidationRule),
            "Should contain InputValidationRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof SqlInjectionRule),
            "Should contain SqlInjectionRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof XssPreventionRule),
            "Should contain XssPreventionRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof CsrfProtectionRule),
            "Should contain CsrfProtectionRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof SecureConfigurationRule),
            "Should contain SecureConfigurationRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof AuthenticationRule),
            "Should contain AuthenticationRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof SessionManagementRule),
            "Should contain SessionManagementRule");
        assertTrue(rules.stream().anyMatch(r -> r instanceof ExceptionHandlingRule),
            "Should contain ExceptionHandlingRule");
    }
    
    @Test
    public void testCreateSpecificRule() {
        // Get the factory instance
        DotNetRuleFactory factory = DotNetRuleFactory.getInstance();
        
        // Create specific rules by ID
        SecurityRule sqlRule = factory.createRule("DOTNET-SEC-003");
        SecurityRule xssRule = factory.createRule("DOTNET-SEC-004");
        SecurityRule nonExistentRule = factory.createRule("DOTNET-SEC-999");
        
        // Verify rule creation
        assertNotNull(sqlRule, "Should create SQL injection rule");
        assertTrue(sqlRule instanceof SqlInjectionRule, "Should be a SqlInjectionRule instance");
        
        assertNotNull(xssRule, "Should create XSS prevention rule");
        assertTrue(xssRule instanceof XssPreventionRule, "Should be a XssPreventionRule instance");
        
        assertNull(nonExistentRule, "Should return null for non-existent rule ID");
    }
    
    @Test
    public void testRegisterCustomRule() {
        // Get the factory instance
        DotNetRuleFactory factory = DotNetRuleFactory.getInstance();
        
        // Create a mock rule supplier
        Supplier<SecurityRule> mockRuleSupplier = () -> new AbstractDotNetSecurityRule(
            "DOTNET-CUSTOM-001", 
            "Custom Test Rule",
            "LOW",
            "Just for testing",
            "https://example.com",
            java.util.regex.Pattern.compile("test")
        ) {
            @Override
            protected boolean checkViolation(String line, int lineNumber, org.emilholmegaard.owaspscanner.core.RuleContext context) {
                return false;
            }
        };
        
        // Register the custom rule
        factory.registerRule("DOTNET-CUSTOM-001", mockRuleSupplier);
        
        // Try to create the custom rule
        SecurityRule customRule = factory.createRule("DOTNET-CUSTOM-001");
        
        // Verify custom rule creation
        assertNotNull(customRule, "Should create custom rule");
        assertEquals("DOTNET-CUSTOM-001", customRule.getId(), "Custom rule should have correct ID");
        assertEquals("Custom Test Rule", customRule.getDescription(), "Custom rule should have correct description");
    }
    
    @Test
    public void testSingletonBehavior() {
        // Get two instances
        DotNetRuleFactory instance1 = DotNetRuleFactory.getInstance();
        DotNetRuleFactory instance2 = DotNetRuleFactory.getInstance();
        
        // Verify that they are the same instance
        assertSame(instance1, instance2, "Factory should be a singleton");
        
        // Register a custom rule on the first instance
        instance1.registerRule("DOTNET-TEST-001", () -> new HttpSecurityHeadersRule());
        
        // Verify that the second instance can create that rule
        assertNotNull(instance2.createRule("DOTNET-TEST-001"), 
            "Second instance should access rules registered on first instance");
    }
}
