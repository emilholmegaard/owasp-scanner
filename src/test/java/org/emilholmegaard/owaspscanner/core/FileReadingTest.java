package org.emilholmegaard.owaspscanner.core;

import org.emilholmegaard.owaspscanner.service.FileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles("test")
class FileReadingTest {

    @Autowired
    private FileService fileService;

    @Autowired
    private BaseScannerEngine scannerEngine;

    @TempDir
    Path tempDir;

    private Path utf8File;
    private Path windows1252File;
    private Path longLineFile;
    private String utf8Content;
    private String windows1252Content;

    @BeforeEach
    void setUp() throws IOException {
        // Create test files with different encodings
        utf8File = tempDir.resolve("utf8_content.txt");
        windows1252File = tempDir.resolve("windows1252_content.txt");
        longLineFile = tempDir.resolve("long_line.txt");

        utf8Content = "Hello, this is UTF-8 text with special characters: ö ä ü ß 日本語 😊";
        Files.write(utf8File, utf8Content.getBytes(StandardCharsets.UTF_8));

        windows1252Content = "This is Windows-1252 content with special characters: € â ê î ô û";
        Files.write(windows1252File, windows1252Content.getBytes("windows-1252"));

        StringBuilder longLine = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            longLine.append("X");
        }
        Files.write(longLineFile, longLine.toString().getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void testReadingUtf8File() throws IOException {
        List<String> content = fileService.readFileWithFallback(utf8File);
        assertNotNull(content);
        assertEquals(utf8Content, content.get(0));

        List<SecurityViolation> violations = scannerEngine.scanFile(utf8File);
        assertNotNull(violations);
    }

    @Test
    void testReadingWindows1252File() throws IOException {
        List<String> content = fileService.readFileWithFallback(windows1252File);
        assertNotNull(content);
        assertEquals(windows1252Content, content.get(0));

        List<SecurityViolation> violations = scannerEngine.scanFile(windows1252File);
        assertNotNull(violations);
    }

    @Test
    void testCaching() throws IOException {
        // First read
        List<SecurityViolation> firstRead = scannerEngine.scanFile(utf8File);
        List<String> firstContent = fileService.readFileWithFallback(utf8File);

        // Second read should use cache
        List<SecurityViolation> secondRead = scannerEngine.scanFile(utf8File);
        List<String> secondContent = fileService.readFileWithFallback(utf8File);

        assertEquals(firstContent, secondContent);
        assertEquals(firstRead, secondRead);
    }

    @Test
    void testClearingCache() throws IOException {
        // First read
        List<String> firstContent = fileService.readFileWithFallback(utf8File);

        // Clear cache
        fileService.clearFileContentCache();

        // Read again
        List<String> secondContent = fileService.readFileWithFallback(utf8File);

        assertEquals(firstContent, secondContent);
    }

    @Test
    void testConcurrentReads() throws InterruptedException {
        int threadCount = 10;
        CountDownLatch latch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    List<String> content = fileService.readFileWithFallback(utf8File);
                    assertNotNull(content);
                    assertEquals(utf8Content, content.get(0));
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(5, TimeUnit.SECONDS));
        executor.shutdown();
    }
}