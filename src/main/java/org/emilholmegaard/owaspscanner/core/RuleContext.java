package org.emilholmegaard.owaspscanner.core;

import java.nio.file.Path;
import java.util.List;

/**
 * Context object that provides additional information for rule checking.
 */
public interface RuleContext {
    /**
     * Returns the path to the file being scanned.
     */
    Path getFilePath();
    
    /**
     * Returns the entire content of the file being scanned.
     */
    List<String> getFileContent();
    
    /**
     * Gets a window of lines around the current line for context.
     *
     * @param lineNumber The current line number
     * @param windowSize The number of lines before and after to include
     * @return A list of lines centered around the specified line
     */
    List<String> getLinesAround(int lineNumber, int windowSize);
}