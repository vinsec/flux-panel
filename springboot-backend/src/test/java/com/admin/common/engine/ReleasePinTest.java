package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class ReleasePinTest {
    @Test
    void releaseCannotUseInsecureOrCredentialBearingOrigins() {
        for (String s :
                new String[] {
                    "http://example/releases",
                    "https://user:password@example/releases",
                    "https://example/releases?token=secret",
                    "https://example/releases#fragment"
                })
            assertThrows(IllegalArgumentException.class, () -> NodeReleaseService.secureBase(s));
        assertEquals(
                "https://example/releases/v3",
                NodeReleaseService.secureBase("https://example/releases/v3/"));
    }

    @Test
    void literalShellValuesRemainQuoted() {
        assertEquals("'a'\"'\"'b'", NodeReleaseService.quoted("a'b"));
    }
}
