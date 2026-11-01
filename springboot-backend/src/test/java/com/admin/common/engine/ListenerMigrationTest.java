package com.admin.common.engine;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.admin.entity.Tunnel;
import com.alibaba.fastjson.JSONObject;
class ListenerMigrationTest {
 private ForwardSpec spec(String engine,String host,String target){Tunnel t=new Tunnel();t.setEngine(engine);t.setTcpListenAddr(host);t.setUdpListenAddr(host);t.setType(1);return new ForwardSpec("1_1_0",50050,null,target,1,t,"fifo",null);}
 @Test void legacyBracketedWildcardBecomesIPv4OnlyForKernelIPv4Targets(){var s=spec("kernel","[::]","192.0.2.2:50050");var v=EngineSpecFactory.listeners(s,new JSONObject());assertEquals("0.0.0.0",v.getJSONObject(0).getString("host"));assertEquals("ipv4",v.getJSONObject(1).getString("family"));assertEquals("[::]",s.getTunnel().getTcpListenAddr());}
 @Test void gostAndExplicitIPv6AreNotSilentlyConverted(){assertEquals("ipv6",EngineSpecFactory.listeners(spec("gost","[::]","192.0.2.2:50050"),new JSONObject()).getJSONObject(0).getString("family"));assertEquals("ipv6",EngineSpecFactory.listeners(spec("kernel","::","192.0.2.2:50050"),new JSONObject()).getJSONObject(0).getString("family"));assertEquals("[2001:db8::1]:443",EngineSpecFactory.join("[2001:db8::1]",443));}
 @Test void unknownTrafficMustStayAllowed(){assertDoesNotThrow(()->EngineSpecFactory.normalizeOptions("{\"protocolFilter\":{\"http\":true,\"tls\":true,\"socks\":true,\"unknown\":\"allow\"}}"));assertThrows(IllegalArgumentException.class,()->EngineSpecFactory.normalizeOptions("{\"protocolFilter\":{\"unknown\":\"drop\"}}"));}

 @Test void nodePolicyIsInBothInteractiveAndReconcileContracts(){
  long id=99991L;var factory=new EngineSpecFactory();var nodes=org.mockito.Mockito.mock(com.admin.mapper.NodeMapper.class);var jdbc=org.mockito.Mockito.mock(org.springframework.jdbc.core.JdbcTemplate.class);
  org.springframework.test.util.ReflectionTestUtils.setField(factory,"nodeMapper",nodes);org.springframework.test.util.ReflectionTestUtils.setField(factory,"jdbc",jdbc);
  var node=new com.admin.entity.Node();node.setHttp(1);node.setTls(1);node.setSocks(1);org.mockito.Mockito.when(nodes.selectById(id)).thenReturn(node);
  EngineCapabilities.register(id,"dpi-test",JSONObject.parseObject("{\"capabilities\":{\"features\":{\"structuredEndpoint\":true,\"independentProtocols\":true,\"protocolBlocking\":true}}}"));
  try {
   var input=spec("kernel","[::]","192.0.2.2:50050");var a=factory.advanced(id,input);var b=factory.advancedForReconcile(id,input);
   assertEquals(5,a.getIntValue("schemaVersion"));assertEquals(a,b);assertEquals("allow",a.getJSONObject("protocolFilter").getString("unknown"));assertTrue(a.getJSONObject("protocolFilter").getBooleanValue("http"));assertEquals("0.0.0.0",a.getJSONArray("listeners").getJSONObject(0).getString("host"));
   node.setHttp(0);node.setTls(0);node.setSocks(0);var off=factory.advancedForReconcile(id,input);assertFalse(off.containsKey("protocolFilter"));assertNotEquals(a.getString("intentHash"),off.getString("intentHash"));
   node.setHttp(1);EngineCapabilities.register(id,"dpi-test",JSONObject.parseObject("{\"capabilities\":{\"features\":{\"structuredEndpoint\":true,\"independentProtocols\":true}}}"));assertThrows(IllegalArgumentException.class,()->factory.advanced(id,input));
  } finally {EngineCapabilities.remove(id,"dpi-test");}
 }
}
