package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class EndpointTest {
    @Test
    void canonicalEndpoints() {
        assertEquals("2001:db8::1", Endpoint.parse("[2001:0db8:0:0:0:0:0:1]:443").getHost());
        assertEquals("::", Endpoint.parse("[::]:80").getHost());
        assertEquals("192.0.2.1", Endpoint.parse("[::ffff:192.0.2.1]:80").getHost());
        assertEquals("example.com", Endpoint.parse("EXAMPLE.com.:443").getHost());
        assertEquals("hostname", Endpoint.parse("origin.example:80").getKind());
    }

    @Test
    void invalidEndpoints() {
        for (String value :
                new String[] {
                    "2001:db8::1:80",
                    "012.0.0.1:80",
                    "[fe80::1%eth0]:80",
                    "user@host:80",
                    "a..b:80",
                    "host:0",
                    "host:65536",
                    " https://host:80"
                }) assertThrows(IllegalArgumentException.class, () -> Endpoint.parse(value), value);
    }

    @Test
    void parsesFutureFamiliesWithoutEnablingThem() {
        assertEquals("ipv6", Endpoint.parse("[2001:db8::2]:443").getFamily());
        assertEquals("auto", Endpoint.parse("origin.example:443").getFamily());
    }
}
