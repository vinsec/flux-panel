package com.admin.common.engine;

import static org.junit.jupiter.api.Assertions.*;

import com.admin.entity.Node;
import com.alibaba.fastjson.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class KernelBackendTest {
    private Node node(String backend) {
        Node n = new Node();
        n.setEngine("kernel");
        n.setKernelBackend(backend);
        n.setSecret("isolated-node-key");
        return n;
    }

    @Test void defaultsAndAliasesNeverReactivateTheRetiredBackend() {
        assertEquals("kernel",EngineRegistry.normalize("iptables"));
        assertEquals("nftables",KernelBackend.forCreate("kernel",null));
        assertEquals("nftables",KernelBackend.forCreate("iptables",null));
        for(String old:new String[]{"iptables","kernel","nft"})
            assertThrows(IllegalArgumentException.class,()->KernelBackend.forCreate("kernel",old));
        assertThrows(IllegalArgumentException.class,()->KernelBackend.forCreate("gost","nftables"));
        assertDoesNotThrow(()->KernelBackend.validateUpdate(node("nftables"),null));
        assertThrows(IllegalArgumentException.class,()->KernelBackend.validateUpdate(node("iptables"),null));
        assertThrows(IllegalArgumentException.class,()->KernelBackend.forNode(node(null)));
        assertTrue(EngineCreditService.reservationVersion("kernel-v6.0"));
        assertTrue(EngineCreditService.reservationVersion("iptables-v5.5"));
    }
    @Test void nativeCapabilityIsMandatory() {
        assertDoesNotThrow(()->KernelBackend.verifyAgent(node("nftables"),JSONObject.parseObject("{\"kernelBackend\":\"nftables\"}")));
        assertThrows(IllegalArgumentException.class,()->KernelBackend.verifyAgent(node("nftables"),new JSONObject()));
        assertThrows(IllegalArgumentException.class,()->KernelBackend.verifyAgent(node("iptables"),new JSONObject()));
        assertThrows(IllegalStateException.class,()->KernelBackend.verifyAgent(node("nftables"),null));
    }

    @Test
    void interactiveAndBatchPathsRejectMismatchBeforeRevisionsOrBilling() {
        long id = 91919193L;
        var nodes = org.mockito.Mockito.mock(com.admin.mapper.NodeMapper.class);
        var revisions = org.mockito.Mockito.mock(EngineRevision.class);
        var credits = org.mockito.Mockito.mock(EngineCreditService.class);
        var jdbc = org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate.class);
        var engine = new KernelForwardingEngine();
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
        var tunnel = new com.admin.entity.Tunnel(); tunnel.setEngine("kernel");
        var spec = new ForwardSpec("1_1_0",18000,null,"10.203.2.2:19000",1,tunnel,"fifo",null);
        for (String desired : new String[] {"nftables", "iptables"}) {
            org.mockito.Mockito.when(nodes.selectById(id)).thenReturn(node(desired));
            JSONObject info = JSONObject.parseObject("{\"capabilities\":{\"features\":{\"batch\":true}}}");
            info.put("kernelBackend", desired.equals("nftables") ? "iptables" : "nftables");
            EngineCapabilities.register(id, "backend-test", info);
            try {
                assertTrue(engine.apply(id, spec, false).getMsg().matches(".*(?:后端|旧 iptables).*"));
                assertTrue(engine.setEnabled(id, "1_1_0", true).getMsg().matches(".*(?:后端|旧 iptables).*"));
                assertTrue(engine.setEnabled(id, "1_1_0", false).getMsg().matches(".*(?:后端|旧 iptables).*"));
                assertTrue(engine.delete(id, "1_1_0").getMsg().matches(".*(?:后端|旧 iptables).*"));
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
        for (String backend : new String[] {"nftables"}) {
            var result = releases.command(node(backend), "panel.invalid");
            assertEquals(0, result.getCode());
            String script = (String) result.getData();
            String json = script.split("<<'FLUX_NODE_CONFIG'\n", 2)[1].split("\nFLUX_NODE_CONFIG", 2)[0];
            JSONObject config = JSONObject.parseObject(json);
            assertEquals(backend, config.getString("kernelBackend"));
            assertTrue(config.getBooleanValue("apply"));
            assertTrue(config.getBooleanValue("useSessions"));
        }
        assertNotEquals(0,releases.command(node("iptables"),"panel.invalid").getCode());
        Node gost = node(null); gost.setEngine("gost");
        String script = (String) releases.command(gost, "panel.invalid").getData();
        assertFalse(script.contains("kernelBackend"));
        assertTrue(script.contains("--engine gost"));
    }
}
