package com.admin;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.admin.common.engine.EngineBatchReconciler;
import com.admin.common.engine.EngineCreditService;
import com.admin.common.engine.EngineTrafficService;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;

/** Run explicitly against the disposable integration DB, never ambient DB vars. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@EnabledIfEnvironmentVariable(named = "FLUX_TEST_DB", matches = "1")
class AdminApplicationTests {
    @Resource EngineCreditService credit;
    @Resource EngineTrafficService traffic;
    @Resource EngineBatchReconciler reconcile;

    @Test
    void foundationServicesAreWired() {
        assertNotNull(credit);
        assertNotNull(traffic);
        assertNotNull(reconcile);
    }
}
