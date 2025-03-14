package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

public class SecureConfigurationRuleTest {

    private SecureConfigurationRule rule;
    
    @Mock
    private RuleContext context;
    
    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        rule = new SecureConfigurationRule();
    }
    
    @Test
    public void testDetectsPlaintextPassword() {
        // Setup
        String line = "  \"Password\": \"secretP@ssw0rd!\",";
        int lineNumber = 5;
        Path path = Paths.get("appsettings.json");
        
        List<String> fileContent = Arrays.asList(
            "{",
            "  \"ConnectionStrings\": {",
            "    \"DefaultConnection\": \"Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=secretP@ssw0rd!;\"",
            "  },",
            "  \"ApiSettings\": {",
            line,
            "    \"Username\": \"admin\"",
            "  }",
            "}"
        );
        
        when(context.getFilePath()).thenReturn(path);
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertTrue(result, "Should detect plaintext password in configuration file");
    }
    
    @Test
    public void testIgnoresPasswordInNonConfigFile() {
        // Setup
        String line = "string password = \"tempPassword\"; // Only for testing";
        int lineNumber = 10;
        Path path = Paths.get("TestClass.cs");
        
        List<String> fileContent = Arrays.asList(
            "public class TestClass {",
            "    public void TestMethod() {",
            line,
            "        // Do something with the password",
            "    }",
            "}"
        );
        
        when(context.getFilePath()).thenReturn(path);
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertFalse(result, "Should not flag passwords in non-configuration files");
    }
    
    @Test
    public void testAcceptsSecureConfiguration() {
        // Setup
        String line = "  \"ConnectionStrings\": {";
        int lineNumber = 3;
        Path path = Paths.get("appsettings.json");
        
        List<String> fileContent = Arrays.asList(
            "{",
            "  \"KeyVaultSettings\": {",
            "    \"VaultUri\": \"https://myvault.vault.azure.net/\"",
            "  },",
            line,
            "    \"DefaultConnection\": \"${KeyVault:ConnectionString}\"",
            "  },",
            "  \"Azure\": {",
            "    \"KeyVault\": {",
            "      \"ClientId\": \"${Environment:KEY_VAULT_CLIENT_ID}\"",
            "    }",
            "  }",
            "}"
        );
        
        when(context.getFilePath()).thenReturn(path);
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertFalse(result, "Should not flag secure configuration with key vault references");
    }
    
    @Test
    public void testAcceptsEnvVarUsage() {
        // Setup
        String line = "      \"SecretKey\": \"${env:SECRET_KEY}\",";
        int lineNumber = 7;
        Path path = Paths.get("appsettings.json");
        
        List<String> fileContent = Arrays.asList(
            "{",
            "  \"AppSettings\": {",
            "    \"ApiUrl\": \"https://api.example.com\",",
            "    \"Secrets\": {",
            line,
            "      \"ApiKey\": \"${env:API_KEY}\"",
            "    }",
            "  }",
            "}"
        );
        
        when(context.getFilePath()).thenReturn(path);
        when(context.getFileContent()).thenReturn(fileContent);
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertFalse(result, "Should not flag configuration using environment variables");
    }
}
