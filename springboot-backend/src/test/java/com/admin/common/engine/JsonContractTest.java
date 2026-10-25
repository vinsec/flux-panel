package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

class JsonContractTest {
    @Test
    void springNestedMapsAreAcceptedWithoutUnsafeCasts() throws Exception {
        JSONObject report =
                new ObjectMapper()
                        .readValue(
                                "{\"usage\":[{\"id\":\"1_2_3\",\"up\":100,\"down\":20}],\"counters\":[{\"id\":\"1_2_3\",\"set\":\"FPV2_UP\",\"key\":\"10.0.0.2,0xf1000100\",\"bytes\":100}]}",
                                JSONObject.class);
        assertEquals(
                1,
                EngineCreditService.validatedCounters(
                                report.getJSONArray("counters"), report.getJSONArray("usage"))
                        .size());
    }
}
