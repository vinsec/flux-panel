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
}
