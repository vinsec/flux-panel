package com.admin.common.engine;

import com.admin.controller.FlowController;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.util.concurrent.*;

import javax.annotation.PreDestroy;
import javax.annotation.Resource;

/** Do not hold accounting row locks while waiting for a node's pause RPC. */
@Service
public class EngineQuotaEnforcer {
    @Resource private FlowController flow;

    private record Owner(String user, String permission, String service) {}

    private final ConcurrentHashMap<String, Owner> pending = new ConcurrentHashMap<>();
    private final ExecutorService workers =
            Executors.newFixedThreadPool(
                    2,
                    r -> {
                        Thread t = new Thread(r, "engine-quota");
                        t.setDaemon(true);
                        return t;
                    });
    private final java.util.Set<String> running = ConcurrentHashMap.newKeySet();

    public void afterCommit(String user, String permission, String service) {
        Runnable add =
                () -> pending.put(user + ":" + permission, new Owner(user, permission, service));
        if (TransactionSynchronizationManager.isSynchronizationActive())
            TransactionSynchronizationManager.registerSynchronization(
                    new TransactionSynchronization() {
                        public void afterCommit() {
                            add.run();
                        }
                    });
        else add.run();
    }

    @Scheduled(fixedDelay = 200, initialDelay = 1000)
    public void drain() {
        for (var e : pending.entrySet()) {
            if (running.size() >= 2) break;
            if (!running.add(e.getKey())) continue;
            Owner owner = pending.remove(e.getKey());
            if (owner == null) {
                running.remove(e.getKey());
                continue;
            }
            workers.submit(
                    () -> {
                        try {
                            flow.enforceEngineLimits(
                                    owner.user(), owner.permission(), owner.service());
                        } catch (Exception error) {
                            pending.putIfAbsent(e.getKey(), owner);
                        } finally {
                            running.remove(e.getKey());
                        }
                    });
        }
    }

    @PreDestroy
    public void stop() {
        workers.shutdownNow();
    }
}
