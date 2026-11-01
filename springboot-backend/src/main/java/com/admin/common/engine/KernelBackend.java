package com.admin.common.engine;
import com.admin.entity.Node;
import com.alibaba.fastjson.JSONObject;
/** Native nftables is the only kernel implementation. Old backend metadata is never reinterpreted. */
public final class KernelBackend {
 private KernelBackend() {}
 public static String forCreate(String engine,String value) {
  if(!"kernel".equals(EngineRegistry.normalize(engine))) {
   if(value!=null&&!value.isBlank())throw new IllegalArgumentException("GOST 节点不使用内核后端");
   return "nftables";
  }
  if(value!=null&&!value.isBlank()&&!value.equals("nftables"))throw new IllegalArgumentException("iptables 后端已移除，内核转发仅支持原生 nftables");
  return "nftables";
 }
 public static String forNode(Node node) {
  if(node==null)throw new IllegalArgumentException("node not found");
  if(!"nftables".equals(node.getKernelBackend()))throw new IllegalArgumentException("旧 iptables 节点不可直接接管，请先使用旧版结算并新建原生 nftables 节点迁移");
  return "nftables";
 }
 public static void validateUpdate(Node node,String requested) {
  if(!"kernel".equals(EngineRegistry.normalize(node.getEngine()))) {
   if(requested!=null&&!requested.isBlank())throw new IllegalArgumentException("GOST 节点不使用内核后端");return;
  }
  forNode(node);
  if(requested!=null&&!requested.isBlank()&&!requested.equals("nftables"))throw new IllegalArgumentException("iptables 后端已移除，不可原地切换");
 }
 public static void verifyAgent(Node node,JSONObject info) {
  forNode(node);
  if(info==null)throw new IllegalStateException("node capabilities unavailable");
  if(!"nftables".equals(info.getString("kernelBackend")))throw new IllegalArgumentException("节点实际内核后端不匹配：仅支持原生 nftables");
 }
}
