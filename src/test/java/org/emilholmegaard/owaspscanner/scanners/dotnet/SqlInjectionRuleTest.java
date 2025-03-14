package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for SqlInjectionRule using AAA pattern and parameterized tests.
 */
public class SqlInjectionRuleTest extends AbstractRuleTest {

    private SqlInjectionRule rule;
    
    @BeforeEach
    public void setUp() {
        super.baseSetUp();
        rule = new SqlInjectionRule();
    }
    
    @ParameterizedTest
    @DisplayName("Should detect SQL injection in vulnerable code")
    @CsvSource({
        // Line number (0-based), Code containing SQL injection vulnerability
        "8, var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\", conn);",
        "4, string query = \"SELECT * FROM Products WHERE Name LIKE '%\" + searchTerm + \"%'\";",
        "3, var users = _context.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Email = '\" + email + \"'\");",
        // Added from the individual test method
        "5, var users = _context.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\").ToList();"
    })
    void shouldDetectSqlInjection(int lineNumber, String vulnerableLine) {
        // Arrange
        List<String> fileContent = codeLines(
            "using System.Data.SqlClient;",
            "public class UserRepository {",
            "    private readonly string connectionString;",
            "    ",
            "    public User GetUser(string username) {",
            "        using (var conn = new SqlConnection(connectionString)) {",
            "            conn.Open();",
            "            // Vulnerable SQL query with string concatenation",
            "            var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\", conn);",
            "            var reader = cmd.ExecuteReader();",
            "            // Process results",
            "            return new User();",
            "        }",
            "    }",
            "}"
        );
        String line = setupTestContext(fileContent, lineNumber, vulnerableLine);
        
        // Act
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Assert
        assertTrue(result, "Should detect SQL injection vulnerability in: " + vulnerableLine);
    }
    
    @ParameterizedTest
    @DisplayName("Should not detect SQL injection in secure code")
    @CsvSource({
        // Line number (0-based), Secure code without SQL injection
        "8, var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = @Username\", conn);",
        "9, cmd.Parameters.AddWithValue(\"@Username\", username);",
        "3, var users = _context.Users.Where(u => u.IsActive).ToList();",
        // Added from the individual test method
        "5, var user = _context.Users.FirstOrDefault(u => u.Username == username);"
    })
    void shouldNotDetectSqlInjectionInSecureCode(int lineNumber, String secureLine) {
        // Arrange
        List<String> fileContent = codeLines(
            "using System.Data.SqlClient;",
            "public class UserRepository {",
            "    private readonly string connectionString;",
            "    ",
            "    public User GetUser(string username) {",
            "        using (var conn = new SqlConnection(connectionString)) {",
            "            conn.Open();",
            "            // Secure parameterized query",
            "            var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Username = @Username\", conn);",
            "            cmd.Parameters.AddWithValue(\"@Username\", username);",
            "            var reader = cmd.ExecuteReader();",
            "            // Process results",
            "            return new User();",
            "        }",
            "    }",
            "}"
        );
        String line = setupTestContext(fileContent, lineNumber, secureLine);
        
        // Act
        boolean result = rule.isViolatedBy(line, lineNumber, context);
        
        // Assert
        assertFalse(result, "Should not detect SQL injection vulnerability in: " + secureLine);
    }
    
    @ParameterizedTest
    @DisplayName("Should analyze SQL in different contexts")
    @CsvSource({
        // filename, line number, code, expected (true=violation, false=secure) 
        "UserRepository.cs, 5, var user = _context.Users.FirstOrDefault(u => u.Username == username);, false",
        "RawSqlInEFCore.cs, 5, var users = _context.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\").ToList();, true"
    })
    void shouldAnalyzeSqlInDifferentContexts(String filename, int lineNumber, String codeLine, boolean expectedViolation) {
        // Arrange
        List<String> fileContent;
        
        if (filename.equals("UserRepository.cs")) {
            fileContent = codeLines(
                "using Microsoft.EntityFrameworkCore;",
                "public class UserRepository {",
                "    private readonly AppDbContext _context;",
                "    public UserRepository(AppDbContext context) => _context = context;",
                "    public User GetUser(string username) {",
                "        var user = _context.Users.FirstOrDefault(u => u.Username == username);",
                "        return user;",
                "    }",
                "}"
            );
        } else {
            fileContent = codeLines(
                "using Microsoft.EntityFrameworkCore;",
                "public class UserRepository {",
                "    private readonly AppDbContext _context;",
                "    public UserRepository(AppDbContext context) => _context = context;",
                "    public List<User> GetUsersByRawSql(string username) {",
                "        var users = _context.Users.FromSqlRaw(\"SELECT * FROM Users WHERE Username = '\" + username + \"'\").ToList();",
                "        return users;",
                "    }",
                "}"
            );
        }
        
        setupTestContext(fileContent, lineNumber, codeLine, Paths.get(filename));
        
        // Act
        boolean result = rule.isViolatedBy(codeLine, lineNumber, context);
        
        // Assert
        if (expectedViolation) {
            assertTrue(result, "Should detect SQL injection in: " + codeLine);
        } else {
            assertFalse(result, "Should not detect SQL injection in: " + codeLine);
        }
    }
    
    @ParameterizedTest
    @DisplayName("Should analyze different ORM patterns")
    @CsvSource({
        // Code pattern, expected (true=violation, false=secure)
        "var result = await _db.Database.ExecuteSqlRawAsync(\"UPDATE Users SET LastLogin = GETDATE() WHERE Username = '\" + username + \"'\");, true",
        "var result = await _db.Database.ExecuteSqlInterpolatedAsync($\"UPDATE Users SET LastLogin = GETDATE() WHERE Username = {username}\");, false",
        "var products = await _context.Products.FromSqlInterpolated($\"SELECT * FROM Products WHERE CategoryId = {categoryId}\").ToListAsync();, false",
        "var count = _context.Database.SqlQuery<int>($\"SELECT COUNT(*) FROM Orders WHERE CustomerId = {customerId}\").FirstOrDefault();, false"
    })
    void shouldAnalyzeDifferentOrmPatterns(String code, boolean expectedViolation) {
        // Arrange
        int lineNumber = 5;
        List<String> fileContent = codeLines(
            "using Microsoft.EntityFrameworkCore;",
            "public class DataRepository {",
            "    private readonly AppDbContext _context;", 
            "    public DataRepository(AppDbContext context) => _context = context;",
            "    public async Task<bool> UpdateUserLastLogin(string username) {",
            "        " + code,
            "        return true;",
            "    }",
            "}"
        );
        
        setupTestContext(fileContent, lineNumber, code);
        
        // Act
        boolean result = rule.isViolatedBy(code, lineNumber, context);
        
        // Assert
        if (expectedViolation) {
            assertTrue(result, "Should detect SQL injection in: " + code);
        } else {
            assertFalse(result, "Should not detect SQL injection in: " + code);
        }
    }
}