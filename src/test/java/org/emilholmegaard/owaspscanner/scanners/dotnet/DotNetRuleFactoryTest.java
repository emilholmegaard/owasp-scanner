package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.SecurityRule;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

// Assuming RuleContext is part of the core package
import org.emilholmegaard.owaspscanner.core.RuleContext;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = { DotNetRuleFactory.class, DotNetRuleFactoryTest.TestConfig.class })
class DotNetRuleFactoryTest {

    @Autowired
    private DotNetRuleFactory ruleFactory;

    @TestConfiguration
    static class TestConfig {
        @Bean
        DotNetRuleFactory ruleFactory() {
            return new DotNetRuleFactory(List.of(mockRule1(), mockRule2()));
        }

        @Bean
        SecurityRule mockRule1() {
            return new TestSecurityRule("MOCK-001", "Mock Rule 1");
        }

        @Bean
        SecurityRule mockRule2() {
            return new TestSecurityRule("MOCK-002", "Mock Rule 2");
        }
    }

    @Test
    void testRuleInjection() {
        List<SecurityRule> rules = ruleFactory.getAllRules();
        assertNotNull(rules, "Rules list should not be null");
        assertFalse(rules.isEmpty(), "Rules list should not be empty");
    }

    @Test
    void testRuleCount() {
        List<SecurityRule> rules = ruleFactory.getAllRules();
        assertEquals(2, rules.size(), "Should have exactly 2 mock rules");
    }

    @Test
    void testRuleContent() {
        List<SecurityRule> rules = ruleFactory.getAllRules();
        boolean foundMock1 = false;
        boolean foundMock2 = false;

        for (SecurityRule rule : rules) {
            if (rule.getId().equals("MOCK-001")) {
                foundMock1 = true;
            } else if (rule.getId().equals("MOCK-002")) {
                foundMock2 = true;
            }
        }

        assertTrue(foundMock1, "Should contain MOCK-001 rule");
        assertTrue(foundMock2, "Should contain MOCK-002 rule");
    }

    // Helper test class for mocking SecurityRule
    private static class TestSecurityRule implements SecurityRule {
        private final String ruleId;
        private final String description;

        TestSecurityRule(String ruleId, String description) {
            this.ruleId = ruleId;
            this.description = description;
        }

        @Override
        public String getDescription() {
            return description;
        }

        @Override
        public String getId() {
            return ruleId;
        }

        @Override
        public String getSeverity() {
            return "LOW"; // Default severity for test purposes
        }

        @Override
        public boolean isViolatedBy(String content, int lineNumber, RuleContext context) {
            return false; // Default implementation for test purposes
        }

        @Override
        public String getReference() {
            return "No reference"; // Default reference for test purposes
        }

        @Override
        public String getRemediation() {
            return "No remediation"; // Default remediation for test purposes
        }
    }
}