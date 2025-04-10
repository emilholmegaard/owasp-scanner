package org.emilholmegaard.owaspscanner.core;

import org.emilholmegaard.owaspscanner.service.FileService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.doAnswer;

@SpringBootTest
@ActiveProfiles("test")
class BaseScannerEngineTest {

    private BaseScannerEngine engine;

    @Mock
    private SecurityScanner mockScanner;

    @Autowired
    private FileService fileService;

    @BeforeEach
    void setUp() {
        System.setProperty("java.util.concurrent.ForkJoinPool.common.parallelism", "4");
        MockitoAnnotations.openMocks(this);
        engine = new BaseScannerEngine(fileService);
        engine.registerScanner(mockScanner);
    }

    @Test
    void testScanFile(@TempDir Path tempDir) throws IOException {
        // Create a test file
        Path testFile = tempDir.resolve("test.cs");
        Files.writeString(testFile, "// Test file content");

        // Create a mock violation
        SecurityViolation mockViolation = new SecurityViolation(
                "TEST-001", "Test violation", testFile, 1,
                "Test snippet", "MEDIUM", "Fix it", "example.com");

        when(mockScanner.canProcessFile(any())).thenReturn(true);
        when(mockScanner.scanFile(testFile)).thenReturn(Collections.singletonList(mockViolation));

        // Scan the file
        List<SecurityViolation> violations = engine.scanFile(testFile);

        // Verify
        assertEquals(1, violations.size());
        assertEquals("TEST-001", violations.get(0).getRuleId());
    }

    @Test
    void testScanDirectory(@TempDir Path tempDir) throws IOException {
        // Create test directory structure
        Path file1 = tempDir.resolve("file1.cs");
        Path file2 = tempDir.resolve("file2.config");

        Files.writeString(file1, "// CS file");
        Files.writeString(file2, "<!-- Config file -->");

        // Setup mock violations
        SecurityViolation violation1 = new SecurityViolation(
                "TEST-001", "Violation in CS file", file1, 1,
                "CS file", "HIGH", "Fix it", "example.com");
        SecurityViolation violation2 = new SecurityViolation(
                "TEST-002", "Violation in config file", file2, 1,
                "Config file", "MEDIUM", "Fix it", "example.com");

        when(mockScanner.canProcessFile(any())).thenReturn(true);
        when(mockScanner.scanFile(file1)).thenReturn(Collections.singletonList(violation1));
        when(mockScanner.scanFile(file2)).thenReturn(Collections.singletonList(violation2));

        // Scan the directory
        List<SecurityViolation> violations = engine.scanDirectory(tempDir);

        // Verify
        assertEquals(2, violations.size());
        assertTrue(violations.stream().anyMatch(v -> v.getRuleId().equals("TEST-001")));
        assertTrue(violations.stream().anyMatch(v -> v.getRuleId().equals("TEST-002")));
    }

    @Test
    @Disabled("Skipping parallel test for now")
    void testParallelFileProcessing(@TempDir Path tempDir) throws IOException {
        // Create test files
        int fileCount = 250;
        for (int i = 0; i < fileCount; i++) {
            Path file = tempDir.resolve("file" + i + ".cs");
            Files.writeString(file, "// CS file " + i);
        }

        // Track execution metrics
        AtomicInteger maxConcurrent = new AtomicInteger(0);
        AtomicInteger currentConcurrent = new AtomicInteger(0);
        Set<String> threadNames = ConcurrentHashMap.newKeySet();
        long startTime = System.currentTimeMillis();

        when(mockScanner.canProcessFile(any())).thenReturn(true);
        doAnswer(invocation -> {
            // Record thread info
            String threadName = Thread.currentThread().getName();
            threadNames.add(threadName);

            // Track concurrent executions
            int current = currentConcurrent.incrementAndGet();
            maxConcurrent.updateAndGet(max -> Math.max(max, current));

            // Simulate work
            Thread.sleep(100); // Longer sleep to ensure overlap

            currentConcurrent.decrementAndGet();

            // Log execution details
            System.out.printf("Thread %s processed file %s%n",
                    threadName, invocation.getArgument(0));

            return Collections.singletonList(new SecurityViolation(
                    "TEST-001", "Test violation",
                    (Path) invocation.getArgument(0), 1,
                    "Test snippet", "MEDIUM", "Fix it", "example.com"));
        }).when(mockScanner).scanFile(any(Path.class));

        // Ensure ForkJoinPool is configured
        System.out.println("ForkJoinPool parallelism: " +
                ForkJoinPool.commonPool().getParallelism());

        // Execute scan
        List<SecurityViolation> violations = engine.scanDirectory(tempDir);
        long duration = System.currentTimeMillis() - startTime;

        // Print diagnostic information
        System.out.println("Execution time: " + duration + "ms");
        System.out.println("Max concurrent executions: " + maxConcurrent.get());
        System.out.println("Unique threads used: " + threadNames.size());
        System.out.println("Thread names: " + String.join(", ", threadNames));

        // Verify results
        assertEquals(fileCount, violations.size());

        // Multiple assertions to verify parallelization
        assertTrue(maxConcurrent.get() > 1,
                "Expected concurrent execution, but max concurrent was: " +
                        maxConcurrent.get());
        assertTrue(threadNames.size() > 1,
                "Expected multiple threads, but got: " + threadNames.size());
        assertTrue(duration < (fileCount * 100),
                "Expected parallel execution to be faster than sequential. Duration: " + duration + "ms");
    }

    @Test
    void testExportToJson(@TempDir Path tempDir) throws IOException {
        Path testFile = tempDir.resolve("test.cs");
        Files.writeString(testFile, "// Test file");

        SecurityViolation violation = new SecurityViolation(
                "TEST-001", "Test violation", testFile, 1,
                "Code snippet", "HIGH", "Fix it", "https://example.com");

        Path outputPath = tempDir.resolve("results.json");
        engine.exportToJson(Collections.singletonList(violation), outputPath);

        assertTrue(Files.exists(outputPath));
        String content = Files.readString(outputPath);
        assertTrue(content.contains("TEST-001"));
        assertTrue(content.contains("Test violation"));
    }
}