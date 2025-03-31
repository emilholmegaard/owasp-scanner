package org.emilholmegaard.owaspscanner.core;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
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
import java.util.stream.Collectors;

import org.emilholmegaard.owaspscanner.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Default implementation of the ScannerEngine interface.
 */
@Component
public class BaseScannerEngine implements ScannerEngine {
    private final List<SecurityScanner> scanners = new ArrayList<>();
    private final FileService fileService;

    @Autowired
    public BaseScannerEngine(FileService fileService) {
        this.fileService = fileService;
    }

    @Override
    public void registerScanner(SecurityScanner scanner) {
        scanners.add(scanner);
    }

    @Override
    public List<SecurityViolation> scanDirectory(Path directoryPath) {
        try {
            ConcurrentLinkedQueue<SecurityViolation> violationsQueue = new ConcurrentLinkedQueue<>();

            Files.walk(directoryPath)
                    .filter(Files::isRegularFile)
                    .parallel()
                    .forEach(filePath -> {
                        try {
                            List<SecurityViolation> fileViolations = scanFile(filePath);
                            violationsQueue.addAll(fileViolations);
                        } catch (Exception e) {
                            System.err.println("Skipping file: " + filePath + " due to: " + e.getMessage());
                        }
                    });

            return new ArrayList<>(violationsQueue);

        } catch (IOException e) {
            System.err.println("Error scanning directory: " + e.getMessage());
            e.printStackTrace();
            return new ArrayList<>();
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
     * Default implementation of RuleContext.
     * Provides file content access and caching mechanisms for efficient rule
     * processing.
     */
    public class DefaultRuleContext implements RuleContext {
        private final Path filePath;
        private final List<String> fileContent;
        private final Map<String, List<String>> lineContextCache = new HashMap<>();
        private final Map<String, String> joinedContextCache = new HashMap<>();

        public DefaultRuleContext(Path filePath) {
            this.filePath = filePath;
            try {
                this.fileContent = fileService.readFileLines(filePath);
            } catch (IOException e) {
                throw new RuntimeException("Failed to read file: " + filePath, e);
            }
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

        /**
         * Gets a window of lines around a specific line number.
         * Results are cached for improved performance on subsequent calls.
         *
         * @param lineNumber the target line number (1-based)
         * @param windowSize number of lines to include before and after the target line
         * @return list of lines within the specified window
         */
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