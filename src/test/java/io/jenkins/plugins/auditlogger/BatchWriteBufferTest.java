package io.jenkins.plugins.auditlogger;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class BatchWriteBufferTest {

    @Test
    public void testBatchThresholdTriggersFlush() {
        List<AuditLogEntry> flushed = Collections.synchronizedList(new ArrayList<>());
        BatchWriteBuffer buffer = new BatchWriteBuffer(3, 5000, flushed::addAll);

        try {
            buffer.add(new AuditLogEntry("user1", "LOGIN", "target", "d1"));
            buffer.add(new AuditLogEntry("user2", "LOGIN", "target", "d2"));
            assertEquals(2, buffer.getCurrentSize());
            assertTrue(flushed.isEmpty());

            // 3rd item reaches batchSize threshold
            buffer.add(new AuditLogEntry("user3", "LOGIN", "target", "d3"));
            assertEquals(0, buffer.getCurrentSize());
            assertEquals(3, flushed.size());
        } finally {
            buffer.shutdown();
        }
    }

    @Test
    public void testPeriodicFlush() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        List<AuditLogEntry> flushed = Collections.synchronizedList(new ArrayList<>());
        BatchWriteBuffer buffer = new BatchWriteBuffer(100, 200, entries -> {
            flushed.addAll(entries);
            latch.countDown();
        });

        try {
            buffer.add(new AuditLogEntry("user1", "BUILD", "job", "d1"));
            boolean fired = latch.await(2, TimeUnit.SECONDS);
            assertTrue(fired, "Periodic flush should have triggered");
            assertEquals(1, flushed.size());
        } finally {
            buffer.shutdown();
        }
    }

    @Test
    public void testManualFlushAndShutdown() {
        List<AuditLogEntry> flushed = Collections.synchronizedList(new ArrayList<>());
        BatchWriteBuffer buffer = new BatchWriteBuffer(50, 10000, flushed::addAll);

        buffer.add(new AuditLogEntry("admin", "CONFIG", "system", "test"));
        assertEquals(1, buffer.getCurrentSize());

        buffer.flush();
        assertEquals(0, buffer.getCurrentSize());
        assertEquals(1, flushed.size());

        buffer.shutdown();
    }
}
