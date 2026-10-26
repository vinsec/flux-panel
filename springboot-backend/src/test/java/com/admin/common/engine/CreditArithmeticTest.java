package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

class CreditArithmeticTest {
    @Test
    void reservationsNeverExceedBillableBudget() {
        for (String ratio : new String[] {"0", "0.000001", "0.1", "0.9", "1", "1.5", "10"})
            for (int flow : new int[] {1, 2})
                for (long available : new long[] {0, 1, 2, 19, 128, 1000000, Long.MAX_VALUE / 4}) {
                    BigDecimal r = new BigDecimal(ratio);
                    long grant = EngineCreditService.rawCredit(available, r, flow, 1048576);
                    assertTrue(grant >= 0 && grant <= 1048576);
                    assertTrue(EngineCreditService.billCeil(grant, r, flow) <= available);
                }
    }

    @Test
    void fractionalBoundaryIsConservative() {
        assertEquals(0, EngineCreditService.rawCredit(1, new BigDecimal("0.000001"), 2, 1000000));
        assertEquals(6, EngineCreditService.rawCredit(19, new BigDecimal("1.5"), 2, 1000));
    }

    @Test
    void overflowAndInvalidBoundsAreRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> EngineCreditService.billCeil(Long.MAX_VALUE, new BigDecimal("2"), 2));
        assertThrows(
                IllegalArgumentException.class,
                () -> EngineCreditService.rawCredit(1, new BigDecimal("-1"), 1, 100));
    }
    @Test
    void bothFamiliesCounterWatermarksUseTheirActualDirection() {
        var usage=com.alibaba.fastjson.JSONArray.parseArray("[{\"id\":\"1_2_3\",\"up\":100,\"down\":20}]");
        for(String set:java.util.List.of("FPV2_UP","FP4_UP","FP6_UP","FPV2_DOWN","FP4_DOWN","FP6_DOWN")) {
            var counters=new com.alibaba.fastjson.JSONArray();var c=new com.alibaba.fastjson.JSONObject();
            c.put("id","1_2_3");c.put("set",set);c.put("key",set.startsWith("FP6")?"2001:db8::1,0xf2000100":"192.0.2.1,0xf2000100");c.put("bytes",set.endsWith("_UP")?100:20);counters.add(c);
            assertEquals(1,EngineCreditService.validatedCounters(counters,usage).size());
            c.put("bytes",set.endsWith("_UP")?101:21);
            assertThrows(IllegalArgumentException.class,()->EngineCreditService.validatedCounters(counters,usage));
        }
    }
}
