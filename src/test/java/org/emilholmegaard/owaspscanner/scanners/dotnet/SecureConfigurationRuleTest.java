package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for SecureConfigurationRule using AAA pattern and parameterized tests.
 */
public class SecureConfigurationRuleTest extends AbstractRuleTest {

    private SecureConfigurationRule rule;
    
    @BeforeEach
    public void setUp() {
        super.baseSetUp();
        rule = new SecureConfigurationRule();
    }
    
    @ParameterizedTest
    @DisplayName("Should detect insecure configurations")
    @CsvSource({
        // filename, line number, line content, expected result (true=violation)
        "appsettings.json, 5, '  \"Password\": \"secretP@ssw0rd!\",', true",
        "appsettings.Development.json, 3, '    \"DefaultConnection\": \"Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=secretP@ssw0rd!;\"', true",
        "web.config, 5, '    <add key=\"AdminPassword\" value=\"admin123\" />', true",
        "config.json, 7, '  \"ApiKey\": \"abcd1234efgh5678\",', true"
    })
    void shouldDetectInsecureConfigurations(String filename, int lineNumber, String lineContent, boolean expectedViolation) {
        // Arrange
        Path path = Paths.get(filename);
        
        List<String> fileContent;
        if (filename.endsWith(".json")) {
            fileContent = Arrays.asList(
                "{",
                "  \"ConnectionStrings\": {",
                "    \"DefaultConnection\": \"Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=secretP@ssw0rd!;\"",
                "  },",
                "  \"ApiSettings\": {",
                "  \"Password\": \"secretP@ssw0rd!\",",
                "    \"Username\": \"admin\"",
                "  }",
                "}"
            );
        } else if (filename.endsWith(".config")) {
            fileContent = Arrays.asList(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<configuration>",
                "  <appSettings>",
                "    <add key=\"ApiUrl\" value=\"https://api.example.com\" />",
                "    <add key=\"AdminPassword\" value=\"admin123\" />",
                "    <add key=\"Username\" value=\"admin\" />",
                "  </appSettings>",
                "</configuration>"
            );
        } else {
            fileContent = Arrays.asList(
                "public class TestClass {",
                "    public void TestMethod() {",
                "string password = \"tempPassword\"; // Only for testing",
                "        // Do something with the password",
                "    }",
                "}"
            );
        }
        
        when(context.getFilePath()).thenReturn(path);
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Act
        boolean result = rule.isViolatedBy(lineContent, lineNumber, context);
        
        // Assert
        if (expectedViolation) {
            assertTrue(result, "Should detect insecure configuration in: " + lineContent);
        } else {
            assertFalse(result, "Should not flag as insecure: " + lineContent);
        }
    }
    
    @ParameterizedTest
    @DisplayName("Should not detect insecure configurations in non-config files")
    @CsvSource({
        "TestClass.cs, 10, 'string password = \"tempPassword\"; // Only for testing', false"
    })
    void shouldNotDetectInsecureConfigurationsInNonConfigFiles(String filename, int lineNumber, String lineContent, boolean expectedViolation) {
        // Arrange
        Path path = Paths.get(filename);
        
        List<String> fileContent = Arrays.asList(
            "public class TestClass {",
            "    public void TestMethod() {",
            "string password = \"tempPassword\"; // Only for testing",
            "        // Do something with the password",
            "    }",
            "}"
        );
        
        when(context.getFilePath()).thenReturn(path);
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Act
        boolean result = rule.isViolatedBy(lineContent, lineNumber, context);
        
        // Assert
        if (expectedViolation) {
            assertTrue(result, "Should detect insecure configuration in: " + lineContent);
        } else {
            assertFalse(result, "Should not flag as insecure: " + lineContent);
        }
    }
    
    @ParameterizedTest
    @DisplayName("Should accept secure configurations")
    @CsvSource({
        // filename, line number, line content
        "appsettings.json, 5, '    \"DefaultConnection\": \"${KeyVault:ConnectionString}\"', false",
        "appsettings.json, 7, '      \"SecretKey\": \"${env:SECRET_KEY}\",', false",
        "appsettings.json, 8, '      \"ApiKey\": \"${ENVIRONMENT:API_KEY}\"', false",
        "web.config, 5, '    <add key=\"Password\" value=\"${KeyVault:AdminPassword}\" />', false",
        "appsettings.json, 10, '      \"ClientId\": \"${Environment:KEY_VAULT_CLIENT_ID}\"', false"
    })
    void shouldAcceptSecureConfigurations(String filename, int lineNumber, String lineContent, boolean expectedViolation) {
        // Arrange
        Path path = Paths.get(filename);
        
        List<String> fileContent;
        if (filename.endsWith(".json")) {
            fileContent = Arrays.asList(
                "{",
                "  \"KeyVaultSettings\": {",
                "    \"VaultUri\": \"https://myvault.vault.azure.net/\"",
                "  },",
                "  \"ConnectionStrings\": {",
                "    \"DefaultConnection\": \"${KeyVault:ConnectionString}\"",
                "  },",
                "  \"Secrets\": {",
                "      \"SecretKey\": \"${env:SECRET_KEY}\",",
                "      \"ApiKey\": \"${ENVIRONMENT:API_KEY}\"",
                "  },",
                "  \"Azure\": {",
                "    \"KeyVault\": {",
                "      \"ClientId\": \"${Environment:KEY_VAULT_CLIENT_ID}\"",
                "    }",
                "  }",
                "}"
            );
        } else {
            fileContent = Arrays.asList(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                "<configuration>",
                "  <appSettings>",
                "    <add key=\"ApiUrl\" value=\"https://api.example.com\" />",
                "    <add key=\"Password\" value=\"${KeyVault:AdminPassword}\" />",
                "    <add key=\"Username\" value=\"admin\" />",
                "  </appSettings>",
                "</configuration>"
            );
        }
        
        when(context.getFilePath()).thenReturn(path);
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Act
        boolean result = rule.isViolatedBy(lineContent, lineNumber, context);
        
        // Assert
        if (expectedViolation) {
            assertTrue(result, "Should detect insecure configuration in: " + lineContent);
        } else {
            assertFalse(result, "Should not flag as secure: " + lineContent);
        }
    }
}