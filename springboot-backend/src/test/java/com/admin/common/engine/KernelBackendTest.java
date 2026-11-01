package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;

import com.admin.entity.Node;
import com.alibaba.fastjson.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class KernelBackendTest {
    private Node node(String backend) {
        Node n = new Node();
        n.setEngine("iptables");
        n.setKernelBackend(backend);
        n.setSecret("isolated-node-key");
        return n;
    }

    @Test
    void newDefaultsDoNotReinterpretLegacyNodes() {
        assertEquals("nftables", KernelBackend.forCreate("iptables", null));
        assertEquals("iptables", KernelBackend.forNode(node(null)));
        assertEquals("iptables", KernelBackend.forCreate("iptables", "iptables"));
        assertThrows(IllegalArgumentException.class, () -> KernelBackend.forCreate("iptables", "nft"));
        assertThrows(IllegalArgumentException.class, () -> KernelBackend.forCreate("gost", "nftables"));
        assertDoesNotThrow(() -> KernelBackend.validateUpdate(node("nftables"), null));
        assertDoesNotThrow(() -> KernelBackend.validateUpdate(node("iptables"), "iptables"));
        assertThrows(IllegalArgumentException.class, () -> KernelBackend.validateUpdate(node("nftables"), "iptables"));
    }

    @Test
    void wrongRuntimeBackendCannotApplyRules() {
        JSONObject legacy = JSONObject.parseObject("{}");
        JSONObject nativeInfo = JSONObject.parseObject("{\"kernelBackend\":\"nftables\"}");
        assertDoesNotThrow(() -> KernelBackend.verifyAgent(node(null), legacy));
        assertDoesNotThrow(() -> KernelBackend.verifyAgent(node("nftables"), nativeInfo));
        assertThrows(IllegalArgumentException.class, () -> KernelBackend.verifyAgent(node("nftables"), legacy));
        assertThrows(IllegalArgumentException.class, () -> KernelBackend.verifyAgent(node("iptables"), nativeInfo));
        assertThrows(IllegalStateException.class, () -> KernelBackend.verifyAgent(node("nftables"), null));
    }

    @Test
    void interactiveAndBatchPathsRejectMismatchBeforeRevisionsOrBilling() {
        long id = 91919193L;
        var nodes = org.mockito.Mockito.mock(com.admin.mapper.NodeMapper.class);
        var revisions = org.mockito.Mockito.mock(EngineRevision.class);
        var credits = org.mockito.Mockito.mock(EngineCreditService.class);
        var jdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate.class);
        var engine = new IptablesForwardingEngine();
        ReflectionTestUtils.setField(engine, "nodes", nodes);
        ReflectionTestUtils.setField(engine, "revisions", revisions);
        ReflectionTestUtils.setField(engine, "credits", credits);
        var batch = new EngineBatchReconciler();
        ReflectionTestUtils.setField(batch, "nodes", nodes);
        ReflectionTestUtils.setField(batch, "jdbc", jdbc);
        ReflectionTestUtils.setField(batch, "ports", new EnginePortPolicy() {
            @Override public <T> T lockedNode(Long node, java.util.function.Supplier<T> action) {
                return action.get();
            }
        });
        var tunnel = new com.admin.entity.Tunnel(); tunnel.setEngine("iptables");
        var spec = new ForwardSpec("1_1_0",18000,null,"10.203.2.2:19000",1,tunnel,"fifo",null);
        for (String desired : new String[] {"nftables", "iptables"}) {
            org.mockito.Mockito.when(nodes.selectById(id)).thenReturn(node(desired));
            JSONObject info = JSONObject.parseObject("{\"capabilities\":{\"features\":{\"batch\":true}}}");
            info.put("kernelBackend", desired.equals("nftables") ? "iptables" : "nftables");
            EngineCapabilities.register(id, "backend-test", info);
            try {
                assertTrue(engine.apply(id, spec, false).getMsg().contains("后端"));
                assertTrue(engine.setEnabled(id, "1_1_0", true).getMsg().contains("后端"));
                assertTrue(engine.setEnabled(id, "1_1_0", false).getMsg().contains("后端"));
                assertTrue(engine.delete(id, "1_1_0").getMsg().contains("后端"));
                assertThrows(IllegalArgumentException.class, () -> batch.reconcile(id));
                org.mockito.Mockito.verifyNoInteractions(revisions, credits, jdbc);
            } finally { EngineCapabilities.remove(id, "backend-test"); }
        }
    }

    @Test
    void generatedInstallerCarriesTheSelectedBackendAndLeavesGostAlone() {
        NodeReleaseService releases = new NodeReleaseService();
        ReflectionTestUtils.setField(releases, "base", "https://example.invalid/releases/frozen");
        ReflectionTestUtils.setField(releases, "manifest", "a".repeat(64));
        ReflectionTestUtils.setField(releases, "installer", "b".repeat(64));
        for (String backend : new String[] {"iptables", "nftables"}) {
            var result = releases.command(node(backend), "panel.invalid");
            assertEquals(0, result.getCode());
            String script = (String) result.getData();
            String json = script.split("<<'FLUX_NODE_CONFIG'\n", 2)[1].split("\nFLUX_NODE_CONFIG", 2)[0];
            JSONObject config = JSONObject.parseObject(json);
            assertEquals(backend, config.getString("kernelBackend"));
            assertTrue(config.getBooleanValue("apply"));
            assertTrue(config.getBooleanValue("useSessions"));
        }
        Node gost = node(null); gost.setEngine("gost");
        String script = (String) releases.command(gost, "panel.invalid").getData();
        assertFalse(script.contains("kernelBackend"));
        assertTrue(script.contains("--engine gost"));
    }
}
