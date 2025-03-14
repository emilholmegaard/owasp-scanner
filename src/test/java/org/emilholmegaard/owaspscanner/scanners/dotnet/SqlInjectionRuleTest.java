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

public class SqlInjectionRuleTest {

    private SqlInjectionRule rule;
    
    @Mock
    private RuleContext context;
    
    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        rule = new SqlInjectionRule();
        when(context.getFilePath()).thenReturn(Paths.get("TestController.cs"));
    }
    
    @Test
    public void testVulnerableStringConcatenation() {
        // Setup
        String line = "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\", conn);";
        int lineNumber = 10;
        List<String> fileContent = Arrays.asList(
            "using System.Data.SqlClient;",
            "public class UserRepository {",
            "    public User GetUser(string username) {",
            "        using (var conn = new SqlConnection(connectionString)) {",
            "            conn.Open();",
            line,
            "            var reader = cmd.ExecuteReader();",
            "            // Process results",
            "        }",
            "    }",
            "}"
        );
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(lineNumber, 5)).thenReturn(fileContent.subList(3, Math.min(fileContent.size(), 8)));
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertTrue(result, "Should detect SQL injection vulnerability due to string concatenation");
    }
    
    @Test
    public void testSafeParameterizedQuery() {
        // Setup
        String line = "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = @Username\", conn);";
        int lineNumber = 10;
        List<String> fileContent = Arrays.asList(
            "using System.Data.SqlClient;",
            "public class UserRepository {",
            "    public User GetUser(string username) {",
            "        using (var conn = new SqlConnection(connectionString)) {",
            "            conn.Open();",
            line,
            "            cmd.Parameters.AddWithValue(\"@Username\", username);",
            "            var reader = cmd.ExecuteReader();",
            "            // Process results",
            "        }",
            "    }",
            "}"
        );
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(lineNumber, 5)).thenReturn(fileContent.subList(4, Math.min(fileContent.size(), 9)));
        when(context.getLinesAround(lineNumber, 10)).thenReturn(fileContent.subList(3, Math.min(fileContent.size(), 13)));
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertFalse(result, "Should not detect SQL injection vulnerability when using parameterized queries");
    }
    
    @Test
    public void testEntityFrameworkUsage() {
        // Setup
        String line = "var user = _context.Users.FirstOrDefault(u => u.Username == username);";
        int lineNumber = 5;
        List<String> fileContent = Arrays.asList(
            "using Microsoft.EntityFrameworkCore;",
            "public class UserRepository {",
            "    private readonly AppDbContext _context;",
            "    public User GetUser(string username) {",
            line,
            "        return user;",
            "    }",
            "}"
        );
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(lineNumber, 5)).thenReturn(fileContent.subList(2, Math.min(fileContent.size(), 7)));
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertFalse(result, "Should not detect SQL injection vulnerability when using Entity Framework");
    }
    
    @Test
    public void testVulnerableRawSqlInEF() {
        // Setup
        String line = "var users = _context.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\").ToList();";
        int lineNumber = 5;
        List<String> fileContent = Arrays.asList(
            "using Microsoft.EntityFrameworkCore;",
            "public class UserRepository {",
            "    private readonly AppDbContext _context;",
            "    public List<User> GetUsersByRawSql(string username) {",
            line,
            "        return users;",
            "    }",
            "}"
        );
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getLinesAround(lineNumber, 5)).thenReturn(fileContent.subList(2, Math.min(fileContent.size(), 7)));
        
        // Execute
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Verify
        assertTrue(result, "Should detect SQL injection vulnerability in raw SQL with Entity Framework");
    }
}
