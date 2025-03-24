package org.emilholmegaard.owaspscanner.scanners.dotnet;

import org.emilholmegaard.owaspscanner.core.RuleContext;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * Base class for rule tests providing common setup and utilities.
 */
public abstract class AbstractRuleTest {
    
    @Mock
    protected RuleContext context;
    
    /**
     * Common setup for all rule tests.
     */
    @BeforeEach
    public void baseSetUp() {
        MockitoAnnotations.openMocks(this);
        
        // Default file path value, can be overridden in specific tests
        when(context.getFilePath()).thenReturn(Paths.get("TestFile.cs"));
    }
    
    /**
     * Sets up the test context with the provided code and line number.
     * 
     * @param fileContent The file content as a list of strings
     * @param lineToTest The line number to test (0-based)
     * @param lineContent The content of the line being tested
     * @param filePath Optional file path, defaults to "TestFile.cs"
     * @return The content of the line to test (for convenience)
     */
    protected String setupTestContext(List<String> fileContent, int lineToTest, String lineContent, Path filePath) {
        when(context.getFileContent()).thenReturn(fileContent);
        when(context.getFilePath()).thenReturn(filePath);
        
        // Set up context.getLinesAround()
        List<String> contextLines = fileContent.subList(
            Math.max(0, lineToTest - 3),
            Math.min(fileContent.size(), lineToTest + 3)
        );
        when(context.getLinesAround(eq(lineToTest), anyInt())).thenReturn(contextLines);
        
        // Set up context.getJoinedLinesAround() with the new method
        when(context.getJoinedLinesAround(eq(lineToTest), anyInt(), anyString())).thenAnswer(invocation -> {
            int windowSize = invocation.getArgument(1);
            String delimiter = invocation.getArgument(2);
            
            int start = Math.max(0, lineToTest - windowSize - 1);
            int end = Math.min(fileContent.size(), lineToTest + windowSize);
            List<String> lines = fileContent.subList(start, end);
            
            return String.join(delimiter, lines);
        });
        
        return lineContent;
    }
    
    /**
     * Sets up the test context with the provided code and line number.
     * Uses the default file path "TestFile.cs".
     */
    protected String setupTestContext(List<String> fileContent, int lineToTest, String lineContent) {
        return setupTestContext(fileContent, lineToTest, lineContent, Paths.get("TestFile.cs"));
    }
    
    /**
     * Creates a list of lines from a code snippet.
     */
    protected List<String> codeLines(String... lines) {
        return Arrays.asList(lines);
    }
}