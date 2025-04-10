package org.emilholmegaard.owaspscanner.performance;

import org.emilholmegaard.owaspscanner.core.BaseScannerEngine;
import org.emilholmegaard.owaspscanner.service.FileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FileReadingPerformanceTest {

    @Autowired
    private FileService fileService;

    private BaseScannerEngine scannerEngine;

    @TempDir
    Path tempDir;

    private List<Path> testFiles;
    private static final int FILE_COUNT = 20;
    private static final int LINES_PER_FILE = 500;

    @BeforeEach
    void setUp() throws IOException {
        scannerEngine = new BaseScannerEngine(fileService);
        testFiles = new ArrayList<>();

        // Create multiple test files with varied content
        for (int i = 0; i < FILE_COUNT; i++) {
            Path filePath = tempDir.resolve("perf_test_file_" + i + ".txt");
            StringBuilder content = new StringBuilder();

            for (int j = 0; j < LINES_PER_FILE; j++) {
                content.append("Line ").append(j).append(" in file ").append(i)
                        .append(": Lorem ipsum dolor sit amet, consectetur adipiscing elit. ")
                        .append("Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n");
            }

            Files.write(filePath, content.toString().getBytes(StandardCharsets.UTF_8));
            testFiles.add(filePath);
        }

        // Set up the mock to return actual file contents
        for (Path file : testFiles) {
            when(fileService.readFileContent(file)).thenReturn(Files.readString(file));
        }
    }

    @Test
    @Disabled("Skipping parallel test for now")
    void testFileReadingPerformanceWithCache() throws IOException {
        // Clear any existing cache
        fileService.clearFileContentCache();
        System.out.println("Starting performance test...");
        long totalFirstReadTime = 0;
        long totalSecondReadTime = 0;

        // Read each file twice, measuring performance
        for (Path file : testFiles) {
            // First read (no cache)
            long startFirst = System.nanoTime();
            scannerEngine.readFileWithFallback(file);
            long firstReadTime = System.nanoTime() - startFirst;
            totalFirstReadTime += firstReadTime;

            // Second read (from cache)
            long startSecond = System.nanoTime();
            scannerEngine.readFileWithFallback(file);
            long secondReadTime = System.nanoTime() - startSecond;
            totalSecondReadTime += secondReadTime;
        }

        long firstReadMs = TimeUnit.NANOSECONDS.toMillis(totalFirstReadTime);
        long secondReadMs = TimeUnit.NANOSECONDS.toMillis(totalSecondReadTime);

        System.out.println("Performance test results:");
        System.out.println("Total time for first reads: " + firstReadMs + " ms");
        System.out.println("Total time for second reads (cached): " + secondReadMs + " ms");
        System.out.println(
                "Performance improvement ratio: " + (float) totalFirstReadTime / totalSecondReadTime + "x faster");
        System.out.println("Time saved: " + (firstReadMs - secondReadMs) + " ms");

        assertTrue(totalSecondReadTime < totalFirstReadTime / 5,
                "Cached reads should be at least 5x faster than uncached reads");
    }

    @Test
    @Disabled("Skipping parallel test for now")
    void testMultipleScansOfSameFiles() {
        // Clear cache to start fresh
        fileService.clearFileContentCache();
        System.out.println("Starting multiple scans performance test...");

        // First scan of all files
        long start1 = System.nanoTime();
        for (Path file : testFiles) {
            scannerEngine.readFileWithFallback(file);
        }
        long firstScanTime = System.nanoTime() - start1;

        // Second scan of all files (should use cache)
        long start2 = System.nanoTime();
        for (Path file : testFiles) {
            scannerEngine.readFileWithFallback(file);
        }
        long secondScanTime = System.nanoTime() - start2;

        long firstScanMs = TimeUnit.NANOSECONDS.toMillis(firstScanTime);
        long secondScanMs = TimeUnit.NANOSECONDS.toMillis(secondScanTime);

        System.out.println("Multiple scans performance test:");
        System.out.println("First scan time: " + firstScanMs + " ms");
        System.out.println("Second scan time: " + secondScanMs + " ms");
        System.out.println("Time saved in second scan: " + (firstScanMs - secondScanMs) + " ms");

        assertTrue(secondScanTime < firstScanTime / 3,
                "Second scan should be at least 3x faster due to caching");
    }

    @Test
    @Disabled("Skipping parallel test for now")
    void testMemoryConsistency() {
        // Clear cache first
        fileService.clearFileContentCache();

        System.out.println("Starting memory consistency test...");

        // Perform 5 complete scans of all files
        for (int scan = 0; scan < 5; scan++) {
            for (Path file : testFiles) {
                scannerEngine.readFileWithFallback(file);
            }

            // Clear cache every other scan to test both cached and uncached behavior
            if (scan % 2 == 1) {
                fileService.clearFileContentCache();
                System.out.println("Cleared cache after scan " + scan);
            }
        }

        System.out.println("Memory consistency test completed successfully");
    }
}