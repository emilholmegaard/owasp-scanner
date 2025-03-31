package org.emilholmegaard.owaspscanner.service;

import org.springframework.stereotype.Service;

import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;

import java.io.IOException;
import java.lang.reflect.Type;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Service for handling file operations with caching and charset detection
 * capabilities.
 * This service provides methods to read files while handling different
 * character encodings
 * and maintaining a thread-safe cache to improve performance for frequently
 * accessed files.
 */
@Service
public class FileService {

    private final Map<Path, CachedFileContent> fileContentCache = new ConcurrentHashMap<>();
    private static final int MAX_LINE_LENGTH = 5000;
    private static final long CACHE_EXPIRY_MINUTES = 30;

    /**
     * Reads a file and returns its contents as a list of strings.
     * This method attempts to read the file using multiple character encodings
     * and caches the result for improved performance on subsequent reads.
     *
     * @param filePath the path to the file to read
     * @return a list of strings, where each string represents a line in the file
     * @throws IOException if the file cannot be read with any of the supported
     *                     charsets
     */
    public List<String> readFileLines(Path filePath) throws IOException {
        // Check cache first
        CachedFileContent cachedContent = fileContentCache.get(filePath);
        if (cachedContent != null && !isCacheExpired(cachedContent.getTimestamp())) {
            return cachedContent.getLines();
        }

        // Try reading with different charsets if UTF-8 fails
        List<Charset> charsets = Arrays.asList(
                StandardCharsets.UTF_8,
                StandardCharsets.ISO_8859_1,
                StandardCharsets.US_ASCII);

        for (Charset charset : charsets) {
            try {
                List<String> lines = Files.readAllLines(filePath, charset)
                        .stream()
                        .map(line -> line.length() > MAX_LINE_LENGTH ? line.substring(0, MAX_LINE_LENGTH) : line)
                        .collect(Collectors.toList());

                // Update cache
                fileContentCache.put(filePath, new CachedFileContent(lines));
                return lines;
            } catch (MalformedInputException e) {
                continue; // Try next charset
            }
        }

        throw new IOException("Unable to read file with supported charsets: " + filePath);
    }

    /**
     * Reads an entire file and returns its contents as a single string.
     * Lines are joined using the newline character.
     *
     * @param filePath the path to the file to read
     * @return the entire file content as a single string
     * @throws IOException if the file cannot be read
     */
    public String readFileContent(Path filePath) throws IOException {
        return String.join("\n", readFileLines(filePath));
    }

    /**
     * Clears the file content cache.
     * This can be called to free memory when needed.
     */
    public void clearFileContentCache() {
        fileContentCache.clear();
    }

    /**
     * Clears the entire file content cache.
     * This can be useful when needing to free memory or ensure fresh reads of
     * files.
     */
    public void clearCache() {
        fileContentCache.clear();
    }

    /**
     * Removes a specific file from the cache.
     * Subsequent reads of this file will fetch fresh content from disk.
     *
     * @param filePath the path of the file to remove from cache
     */
    public void removeFromCache(Path filePath) {
        fileContentCache.remove(filePath);
    }

    /**
     * Checks if a cached entry has expired based on the configured expiry time.
     *
     * @param timestamp the timestamp to check
     * @return true if the cache entry has expired, false otherwise
     */
    private boolean isCacheExpired(Instant timestamp) {
        return timestamp.isBefore(
                Instant.now().minus(CACHE_EXPIRY_MINUTES, java.time.temporal.ChronoUnit.MINUTES));
    }

    /**
     * Helper method to read file content with optimized encoding detection and
     * caching.
     * 
     * @param filePath the path to the file to read
     * @return a list of lines from the file, or an empty list if all read attempts
     *         fail
     */
    public List<String> readFileWithFallback(Path filePath) {
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
        List<String> lines = readFileWithOptimizedEncoding(filePath);

        // Cache the content
        fileContentCache.put(filePath, new CachedFileContent(lines));

        return lines;
    }

    /**
     * Reads file content with optimized encoding detection.
     * 
     * @param filePath the path to the file to read
     * @return a list of lines from the file
     */
    private List<String> readFileWithOptimizedEncoding(Path filePath) {
        // Try UTF-8 first as it's the most common encoding
        try {
            return readLinesWithLengthLimit(Files.readAllLines(filePath, StandardCharsets.UTF_8));
        } catch (MalformedInputException e) {
            // If UTF-8 fails, try other common encodings
            List<Charset> fallbackCharsets = Arrays.asList(
                    Charset.forName("windows-1252"),
                    StandardCharsets.ISO_8859_1,
                    StandardCharsets.UTF_16LE,
                    StandardCharsets.UTF_16BE);

            for (Charset charset : fallbackCharsets) {
                try {
                    return readLinesWithLengthLimit(Files.readAllLines(filePath, charset));
                } catch (MalformedInputException ex) {
                    // Try next encoding
                    continue;
                } catch (IOException ex) {
                    // For other IO issues, try binary fallback
                    break;
                }
            }

            // If all encodings fail, use binary fallback with replacements
            return readWithBinaryFallback(filePath);
        } catch (IOException e) {
            // For other IO errors, try binary fallback
            return readWithBinaryFallback(filePath);
        }
    }

    /**
     * Applies length limiting to each line to prevent excessive memory use
     * 
     * @param lines the list of lines to process
     * @return a list of lines with length limiting applied
     */
    private List<String> readLinesWithLengthLimit(List<String> lines) {
        return lines.stream()
                .map(line -> line.length() > MAX_LINE_LENGTH
                        ? line.substring(0, MAX_LINE_LENGTH) + "... [truncated]"
                        : line)
                .collect(Collectors.toList());
    }

    /**
     * Reads file using binary fallback with replacement for invalid characters
     * 
     * @param filePath the path to the file to read
     * @return a list of lines from the file, or an empty list if read fails
     */
    private List<String> readWithBinaryFallback(Path filePath) {
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
            List<String> lines = new ArrayList<>(splitLines.length);
            for (String line : splitLines) {
                if (line.length() > MAX_LINE_LENGTH) {
                    lines.add(line.substring(0, MAX_LINE_LENGTH) + "... [truncated]");
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
     * Internal class for storing cached file content along with metadata.
     * This class is immutable to ensure thread safety.
     */
    private static class CachedFileContent {
        private final List<String> lines;
        private final Instant timestamp;

        /**
         * Creates a new cache entry with the given content and current timestamp.
         *
         * @param lines the file content as a list of strings
         */
        public CachedFileContent(List<String> lines) {
            this.lines = lines;
            this.timestamp = Instant.now();
        }

        /**
         * Returns the cached file content.
         *
         * @return list of strings representing the file lines
         */
        public List<String> getLines() {
            return lines;
        }

        /**
         * Returns the timestamp when this cache entry was created.
         *
         * @return the creation timestamp of this cache entry
         */
        public Instant getTimestamp() {
            return timestamp;
        }
    }
}