package org.emilholmegaard.owaspscanner.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.Charset;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Default implementation of the ScannerEngine interface.
 */
public class BaseScannerEngine implements ScannerEngine {
    private final List<SecurityScanner> scanners = new ArrayList<>();
    
    @Override
    public void registerScanner(SecurityScanner scanner) {
        scanners.add(scanner);
    }
    
    @Override
    public List<SecurityViolation> scanDirectory(Path directoryPath) {
        List<SecurityViolation> allViolations = new ArrayList<>();
        
        try {
            Files.walk(directoryPath)
                .filter(Files::isRegularFile)
                .forEach(filePath -> {
                    try {
                        allViolations.addAll(scanFile(filePath));
                    } catch (Exception e) {
                        // Skip problematic files and continue scanning
                        System.err.println("Skipping file: " + filePath + " due to: " + e.getMessage());
                    }
                });
        } catch (IOException e) {
            System.err.println("Error scanning directory: " + e.getMessage());
            e.printStackTrace();
        }
        
        return allViolations;
    }
    
    @Override
    public List<SecurityViolation> scanFile(Path filePath) {
        List<SecurityViolation> violations = new ArrayList<>();
        
        // Find appropriate scanner for this file
        for (SecurityScanner scanner : scanners) {
            if (scanner.canProcessFile(filePath)) {
                try {
                    List<SecurityViolation> fileViolations = scanner.scanFile(filePath);
                    violations.addAll(fileViolations);
                } catch (Exception e) {
                    // Only print full stack trace for non-encoding errors
                    if (!(e instanceof MalformedInputException)) {
                        System.err.println("Error scanning file " + filePath + ": " + e.getMessage());
                        e.printStackTrace();
                    } else {
                        System.err.println("Skipping file due to encoding issues: " + filePath);
                    }
                }
            }
        }
        
        return violations;
    }
    
    @Override
    public void exportToJson(List<SecurityViolation> violations, Path outputPath) {
        // Create custom Gson with a Path serializer to avoid stack overflow
        Gson gson = new GsonBuilder()
            .setPrettyPrinting()
            .registerTypeAdapter(Path.class, new PathSerializer())
            .create();
        
        String json = gson.toJson(violations);
        
        try {
            if (outputPath.getParent() != null) {
                Files.createDirectories(outputPath.getParent());
            }
            Files.writeString(outputPath, json);
            System.out.println("Scan results exported to " + outputPath);
        } catch (IOException e) {
            System.err.println("Error exporting results to JSON: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Custom serializer for Path objects to avoid stack overflow
     */
    private static class PathSerializer implements JsonSerializer<Path> {
        @Override
        public JsonElement serialize(Path src, Type typeOfSrc, JsonSerializationContext context) {
            return new JsonPrimitive(src.toString());
        }
    }

    /**
     * Helper method to read file content with fallback encodings.
     * @param filePath the path to the file to read
     * @return a list of lines from the file, or an empty list if all read attempts fail
     */
    public static List<String> readFileWithFallback(Path filePath) {
        // Try common encodings in sequence
        List<String> encodings = Arrays.asList(
            "UTF-8", 
            "windows-1252", 
            "ISO-8859-1",
            "UTF-16LE",
            "UTF-16BE"
        );
        
        for (String encoding : encodings) {
            try {
                return Files.readAllLines(filePath, Charset.forName(encoding));
            } catch (MalformedInputException e) {
                // If we get encoding errors, try the next encoding
                continue;
            } catch (IOException e) {
                // For other types of IO errors, try binary fallback
                break;
            }
        }
        
        // Binary fallback - read as bytes and replace invalid chars
        try {
            byte[] bytes = Files.readAllBytes(filePath);
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
            
            ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            CharBuffer charBuffer = decoder.decode(byteBuffer);
            String content = charBuffer.toString();
            
            // Split by common line separators (handle both Windows and Unix line endings)
            return Arrays.asList(content.split("\\r?\\n"));
        } catch (IOException e) {
            // If all methods fail, return an empty list
            System.err.println("Failed to read file with any encoding: " + filePath);
            return new ArrayList<>();
        }
    }

    /**
     * Default implementation of RuleContext.
     */
    public static class DefaultRuleContext implements RuleContext {
        private final Path filePath;
        private final List<String> fileContent;
        
        public DefaultRuleContext(Path filePath) {
            this.filePath = filePath;
            this.fileContent = readFileWithFallback(filePath);
        }
        
        public DefaultRuleContext(Path filePath, List<String> preReadContent) {
            this.filePath = filePath;
            this.fileContent = preReadContent;
        }
        
        @Override
        public Path getFilePath() {
            return filePath;
        }
        
        @Override
        public List<String> getFileContent() {
            return fileContent;
        }
        
        @Override
        public List<String> getLinesAround(int lineNumber, int windowSize) {
            int start = Math.max(0, lineNumber - windowSize - 1);
            int end = Math.min(fileContent.size(), lineNumber + windowSize);
            
            return fileContent.subList(start, end);
        }
    }
}