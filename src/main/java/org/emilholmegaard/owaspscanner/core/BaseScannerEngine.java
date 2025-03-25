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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Default implementation of the ScannerEngine interface.
 */
public class BaseScannerEngine implements ScannerEngine {
    private final List<SecurityScanner> scanners = new ArrayList<>();
    
    /**
     * Configuration for this scanner engine
     */
    private ScannerConfig config = ScannerConfig.defaultConfig();
    
    /**
     * Cache for storing file content to avoid redundant file reads.
     * The key is the file path, and the value is a CachedFileContent object.
     */
    private static final Map<Path, CachedFileContent> fileContentCache = new ConcurrentHashMap<>();
    
    /**
     * Default maximum length of a line to be processed without truncation
     */
    private static final int DEFAULT_MAX_LINE_LENGTH = 5000;
    
    @Override
    public void registerScanner(SecurityScanner scanner) {
        scanners.add(scanner);
    }
    
    @Override
    public void setConfig(ScannerConfig config) {
        this.config = config;
    }
    
    @Override
    public ScannerConfig getConfig() {
        return config;
    }
    
    @Override
    public List<SecurityViolation> scanDirectory(Path directoryPath) {
        try {
            Stream<Path> fileStream = Files.walk(directoryPath)
                .filter(Files::isRegularFile)
                .filter(this::isFileSizeAcceptable);
            
            if (config.isParallelProcessing()) {
                ForkJoinPool customThreadPool = new ForkJoinPool(config.getMaxThreads());
                try {
                    return customThreadPool.submit(() -> 
                        fileStream.parallel()
                            .flatMap(this::scanFileToStream)
                            .collect(Collectors.toList())
                    ).get();
                } catch (InterruptedException | ExecutionException e) {
                    System.err.println("Error in parallel processing: " + e.getMessage());
                    // Fallback to sequential processing
                    fileStream = Files.walk(directoryPath)
                        .filter(Files::isRegularFile)
                        .filter(this::isFileSizeAcceptable);
                    
                    return fileStream
                        .flatMap(this::scanFileToStream)
                        .collect(Collectors.toList());
                }
            } else {
                return fileStream
                    .flatMap(this::scanFileToStream)
                    .collect(Collectors.toList());
            }
        } catch (IOException e) {
            System.err.println("Error scanning directory: " + e.getMessage());
            e.printStackTrace();
            return new ArrayList<>();
        }
    }
    
    /**
     * Helper method to convert file scanning to a stream of violations
     */
    private Stream<SecurityViolation> scanFileToStream(Path filePath) {
        try {
            List<SecurityViolation> violations = scanFile(filePath);
            return violations.stream();
        } catch (Exception e) {
            System.err.println("Skipping file: " + filePath + " due to: " + e.getMessage());
            return Stream.empty();
        }
    }
    
    /**
     * Check if file size is within acceptable limit
     */
    private boolean isFileSizeAcceptable(Path filePath) {
        try {
            return Files.size(filePath) <= config.getMaxFileSizeBytes();
        } catch (IOException e) {
            return false;
        }
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
                    
                    // Apply early termination if configured
                    if (config.isEarlyTermination() && violations.size() >= config.getMaxViolationsPerFile()) {
                        System.out.println("Early termination applied for file: " + filePath + 
                            " after finding " + violations.size() + " violations");
                        break;
                    }
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
        
        // Limit number of violations if needed
        if (violations.size() > config.getMaxViolationsPerFile()) {
            return violations.subList(0, config.getMaxViolationsPerFile());
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
     * Class for storing cached file content with metadata
     */
    private static class CachedFileContent {
        private final List<String> lines;
        private final Instant timestamp;
        
        public CachedFileContent(List<String> lines) {
            this.lines = lines;
            this.timestamp = Instant.now();
        }
        
        public List<String> getLines() {
            return lines;
        }
        
        public Instant getTimestamp() {
            return timestamp;
        }
    }

    /**
     * Helper method to read file content with optimized encoding detection and caching.
     * 
     * @param filePath the path to the file to read
     * @return a list of lines from the file, or an empty list if all read attempts fail
     */
    public List<String> readFileWithFallback(Path filePath) {
        // If caching is disabled, read the file directly without caching
        if (!config.isCacheFileContent()) {
            return readFileWithOptimizedEncoding(filePath, config.getMaxLineLengthBytes());
        }
        
        try {
            // Check if file was modified since it was cached
            if (fileContentCache.containsKey(filePath)) {
                Instant fileLastModified = Files.getLastModifiedTime(filePath).toInstant();
                CachedFileContent cachedContent = fileContentCache.get(filePath);
                
                // If file hasn't been modified since it was cached, return cached content
                if (!fileLastModified.isAfter(cachedContent.getTimestamp())) {
                    return cachedContent.getLines();
                }
            }
        } catch (IOException e) {
            // If we can't check file modification time, proceed with regular reading
            // but still check cache first
            if (fileContentCache.containsKey(filePath)) {
                return fileContentCache.get(filePath).getLines();
            }
        }
        
        // File wasn't in cache or was modified, so read it
        List<String> lines = readFileWithOptimizedEncoding(filePath, config.getMaxLineLengthBytes());
        
        // Cache the content if caching is enabled
        if (config.isCacheFileContent()) {
            fileContentCache.put(filePath, new CachedFileContent(lines));
        }
        
        return lines;
    }
    
    /**
     * Static helper method to read file content with optimized encoding detection.
     * This is provided for compatibility with code that can't access the instance method.
     * 
     * @param filePath the path to the file to read
     * @return a list of lines from the file
     */
    public static List<String> readFileWithFallback(Path filePath) {
        // Use default configuration
        return readFileWithOptimizedEncoding(filePath, DEFAULT_MAX_LINE_LENGTH);
    }
    
    /**
     * Reads file content with optimized encoding detection.
     * 
     * @param filePath the path to the file to read
     * @param maxLineLength maximum length for each line
     * @return a list of lines from the file
     */
    private static List<String> readFileWithOptimizedEncoding(Path filePath, long maxLineLength) {
        // Try UTF-8 first as it's the most common encoding
        try {
            return readLinesWithLengthLimit(Files.readAllLines(filePath, StandardCharsets.UTF_8), maxLineLength);
        } catch (MalformedInputException e) {
            // If UTF-8 fails, try other common encodings
            List<Charset> fallbackCharsets = Arrays.asList(
                Charset.forName("windows-1252"),
                StandardCharsets.ISO_8859_1,
                StandardCharsets.UTF_16LE,
                StandardCharsets.UTF_16BE
            );
            
            for (Charset charset : fallbackCharsets) {
                try {
                    return readLinesWithLengthLimit(Files.readAllLines(filePath, charset), maxLineLength);
                } catch (MalformedInputException ex) {
                    // Try next encoding
                    continue;
                } catch (IOException ex) {
                    // For other IO issues, try binary fallback
                    break;
                }
            }
            
            // If all encodings fail, use binary fallback with replacements
            return readWithBinaryFallback(filePath, maxLineLength);
        } catch (IOException e) {
            // For other IO errors, try binary fallback
            return readWithBinaryFallback(filePath, maxLineLength);
        }
    }
    
    /**
     * Applies length limiting to each line to prevent excessive memory use
     * 
     * @param lines the list of lines to process
     * @param maxLineLength maximum length for each line
     * @return a list of lines with length limiting applied
     */
    private static List<String> readLinesWithLengthLimit(List<String> lines, long maxLineLength) {
        int maxLength = (int) maxLineLength;
        return lines.stream()
            .map(line -> line.length() > maxLength 
                ? line.substring(0, maxLength) + "... [truncated]" 
                : line)
            .collect(Collectors.toList());
    }
    
    /**
     * Reads file using binary fallback with replacement for invalid characters
     * 
     * @param filePath the path to the file to read
     * @param maxLineLength maximum length for each line
     * @return a list of lines from the file, or an empty list if read fails
     */
    private static List<String> readWithBinaryFallback(Path filePath, long maxLineLength) {
        try {
            byte[] bytes = Files.readAllBytes(filePath);
            CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
            
            ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
            CharBuffer charBuffer = decoder.decode(byteBuffer);
            String content = charBuffer.toString();
            
            // Split by common line separators (handle both Windows and Unix line endings)
            String[] splitLines = content.split("\\r?\\n");
            
            // Apply length limiting
            int maxLength = (int) maxLineLength;
            List<String> lines = new ArrayList<>(splitLines.length);
            for (String line : splitLines) {
                if (line.length() > maxLength) {
                    lines.add(line.substring(0, maxLength) + "... [truncated]");
                } else {
                    lines.add(line);
                }
            }
            
            return lines;
        } catch (IOException e) {
            // If all methods fail, return an empty list
            System.err.println("Failed to read file with any encoding: " + filePath);
            return new ArrayList<>();
        }
    }
    
    /**
     * Clears the file content cache.
     * This can be called to free memory when needed.
     */
    public static void clearFileContentCache() {
        fileContentCache.clear();
    }

    /**
     * Default implementation of RuleContext.
     */
    public class DefaultRuleContext implements RuleContext {
        private final Path filePath;
        private final List<String> fileContent;
        
        // Cache for lines around context to avoid redundant list creation
        private final Map<String, List<String>> lineContextCache = new HashMap<>();
        
        // Cache for joined context strings to avoid redundant string joining
        private final Map<String, String> joinedContextCache = new HashMap<>();
        
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
            // Create a cache key based on line number and window size
            String cacheKey = lineNumber + ":" + windowSize;
            
            // Check cache first
            if (lineContextCache.containsKey(cacheKey)) {
                return lineContextCache.get(cacheKey);
            }
            
            // Calculate line range
            int start = Math.max(0, lineNumber - windowSize - 1);
            int end = Math.min(fileContent.size(), lineNumber + windowSize);
            
            // Create and cache the context lines
            List<String> contextLines = fileContent.subList(start, end);
            lineContextCache.put(cacheKey, contextLines);
            
            return contextLines;
        }
        
        @Override
        public String getJoinedLinesAround(int lineNumber, int windowSize, String delimiter) {
            // Create a cache key based on line number, window size, and delimiter
            String cacheKey = lineNumber + ":" + windowSize + ":" + delimiter;
            
            // Check cache first
            if (joinedContextCache.containsKey(cacheKey)) {
                return joinedContextCache.get(cacheKey);
            }
            
            // Get context lines
            List<String> contextLines = getLinesAround(lineNumber, windowSize);
            
            // Join and cache the result
            String joinedContext = String.join(delimiter, contextLines);
            joinedContextCache.put(cacheKey, joinedContext);
            
            return joinedContext;
        }
    }
}
