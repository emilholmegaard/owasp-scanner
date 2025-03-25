package org.emilholmegaard.owaspscanner.scanners;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.core.ScannerConfig;
import org.emilholmegaard.owaspscanner.core.SecurityViolation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for the DotNetScanner with dependency injection.
 */
public class DotNetScannerTest {

    @TempDir
    Path tempDir;
    
    @Mock
    BaseScannerEngine mockEngine;
    
    private DotNetScanner scanner;
    private Path csharpFile;
    
    @BeforeEach
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);
        
        // Set up the mock engine
        when(mockEngine.readFileWithFallback(any(Path.class)))
            .thenAnswer(invocation -> {
                Path path = invocation.getArgument(0);
                return Files.readAllLines(path, StandardCharsets.UTF_8);
            });
        
        when(mockEngine.getConfig()).thenReturn(ScannerConfig.defaultConfig());
        
        // Create a test C# file
        csharpFile = tempDir.resolve("Test.cs");
        String csharpContent = 
            "using System;\n" +
            "using System.Web.UI;\n" +
            "\n" +
            "namespace TestApp {\n" +
            "    public class Test {\n" +
            "        public void ProcessInput(string input) {\n" +
            "            // SQL Injection vulnerability\n" +
            "            string query = \"SELECT * FROM Users WHERE Name = '\" + input + \"'\";\n" +
            "            \n" +
            "            // XSS vulnerability\n" +
            "            Response.Write(\"<div>\" + input + \"</div>\");\n" +
            "        }\n" +
            "    }\n" +
            "}";
        Files.writeString(csharpFile, csharpContent, StandardCharsets.UTF_8);
    }
    
    @Test
    public void testDefaultConstructor() {
        // Create scanner with default constructor
        scanner = new DotNetScanner();
        
        // Verify it's properly initialized
        assertEquals("OWASP .NET Security Scanner", scanner.getName());
        assertEquals("DotNet", scanner.getTechnology());
        assertTrue(scanner.getSupportedFileExtensions().contains("cs"));
        assertTrue(scanner.getSupportedFileExtensions().contains("cshtml"));
    }
    
    @Test
    public void testConstructorWithEngine() {
        // Create scanner with engine dependency injection
        scanner = new DotNetScanner(mockEngine);
        
        // Verify it's properly initialized
        assertEquals("OWASP .NET Security Scanner", scanner.getName());
        assertTrue(scanner.getSupportedFileExtensions().contains("cs"));
    }
    
    @Test
    public void testCanProcessFile() {
        // Create scanner
        scanner = new DotNetScanner(mockEngine);
        
        // Test supported file types
        assertTrue(scanner.canProcessFile(Path.of("test.cs")));
        assertTrue(scanner.canProcessFile(Path.of("test.cshtml")));
        assertTrue(scanner.canProcessFile(Path.of("web.config")));
        assertTrue(scanner.canProcessFile(Path.of("project.csproj")));
        
        // Test unsupported file types
        assertFalse(scanner.canProcessFile(Path.of("test.java")));
        assertFalse(scanner.canProcessFile(Path.of("test.js")));
        assertFalse(scanner.canProcessFile(Path.of("test.html")));
    }
    
    @Test
    public void testScanFileUsesDependencyInjection() throws IOException {
        // Create scanner with mock engine
        scanner = new DotNetScanner(mockEngine);
        
        // Scan the test file
        scanner.scanFile(csharpFile);
        
        // Verify the engine was used to read the file
        verify(mockEngine).readFileWithFallback(eq(csharpFile));
    }
}
