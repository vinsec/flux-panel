package com.admin.controller;

import com.admin.common.annotation.RequireRole;
import com.admin.common.engine.*;
import com.admin.common.lang.R;
import com.admin.common.utils.*;
import com.alibaba.fastjson.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.*;

@RestController @RequestMapping("/api/v1/engine")
public class EngineStateController {
    @Resource private JdbcTemplate jdbc;
    @Resource private NodeCredentials credentials;
    @Resource private IptablesForwardingEngine engine;
    @PostMapping("/tunnel-capabilities")
    public R tunnelCapabilities(@RequestBody JSONObject input){
        long tunnel=input.getLongValue("tunnelId"),user=JwtUtil.getUserIdFromToken();var rows=jdbc.queryForList("SELECT in_node_id,engine,tcp_listen_addr,udp_listen_addr FROM tunnel WHERE id=?",tunnel);if(rows.isEmpty())return R.err("隧道不存在");
        if(JwtUtil.getRoleIdFromToken()!=0&&jdbc.queryForObject("SELECT COUNT(*) FROM user_tunnel WHERE user_id=? AND tunnel_id=? AND status=1 AND exp_time>?",Integer.class,user,tunnel,System.currentTimeMillis())==0)return R.err("无隧道权限");
        var row=rows.get(0);JSONObject info=new JSONObject();info.put("engine",row.get("engine"));info.put("tcpListenAddr",row.get("tcp_listen_addr"));info.put("udpListenAddr",row.get("udp_listen_addr"));if("iptables".equals(row.get("engine")))info.put("node",EngineCapabilities.negotiate(((Number)row.get("in_node_id")).longValue()));return R.ok(info);
    }
    @PostMapping("/forward-states")
    public R states(@RequestBody JSONObject input){
        JSONArray ids=input.getJSONArray("ids");if(ids==null||ids.isEmpty()||ids.size()>200)return R.err("status page requires 1..200 forwarding IDs");
        Set<Long> requested=new LinkedHashSet<>();for(Object id:ids)requested.add(Long.parseLong(id.toString()));
        String placeholders=String.join(",",Collections.nCopies(requested.size(),"?"));var rows=jdbc.queryForList("SELECT f.id,f.user_id,t.in_node_id,t.engine,u.role_id,ut.id permission_id FROM forward f JOIN tunnel t ON t.id=f.tunnel_id JOIN user u ON u.id=f.user_id LEFT JOIN user_tunnel ut ON ut.user_id=f.user_id AND ut.tunnel_id=f.tunnel_id WHERE f.id IN ("+placeholders+")",requested.toArray());
        long user=JwtUtil.getUserIdFromToken();boolean admin=JwtUtil.getRoleIdFromToken()==0;Map<Long,Map<String,Long>> groups=new HashMap<>();JSONArray output=new JSONArray();
        for(var row:rows){long owner=((Number)row.get("user_id")).longValue();if(!admin&&owner!=user)return R.err("转发不存在或无权限");long id=((Number)row.get("id")).longValue(),node=((Number)row.get("in_node_id")).longValue();if(!"iptables".equals(row.get("engine")))continue;long permission=((Number)row.get("role_id")).intValue()==0?0:row.get("permission_id")==null?-1:((Number)row.get("permission_id")).longValue();if(permission<0)continue;groups.computeIfAbsent(node,n->new LinkedHashMap<>()).put(id+"_"+owner+"_"+permission,id);}
        for(var group:groups.entrySet()){List<String> names=new ArrayList<>(group.getValue().keySet());for(int offset=0;offset<names.size();offset+=100){List<String> page=names.subList(offset,Math.min(offset+100,names.size()));JSONObject query=new JSONObject();query.put("ids",page);var reply=WebSocketServer.send_msg(group.getKey(),query,"GetForwardStatuses");JSONObject data="OK".equals(reply.getMsg())?(JSONObject)JSONObject.toJSON(reply.getData()):null;for(String name:page){JSONObject value=new JSONObject();value.put("id",group.getValue().get(name));value.put("state",data==null?Map.of("status","unavailable"):data.get(name));output.add(value);}}}
        return R.ok(output);
    }
    @PostMapping("/bandwidth-groups") @RequireRole
    public R groups(@RequestBody JSONObject input){return R.ok(jdbc.queryForList("SELECT scope,owner_id ownerId,up_bits upBitsPerSecond,down_bits downBitsPerSecond FROM engine_bandwidth_group WHERE node_id=?",input.getLong("nodeId")));}
    @PostMapping("/set-bandwidth-group") @RequireRole
    public R setGroup(@RequestBody JSONObject input){
        long node=input.getLongValue("nodeId"),owner=input.getLongValue("ownerId");String scope=input.getString("scope");if(!Set.of("user","userTunnel").contains(scope)||owner<1)return R.err("invalid bandwidth group scope");EngineCapabilities.require(node,"shaping");long up,down;try{up=exactRate(input,"upBitsPerSecond");down=exactRate(input,"downBitsPerSecond");}catch(Exception e){return R.err("bit rates must be exact integers");}for(long rate:new long[]{up,down})if(rate!=0&&(rate<1000||rate>1000000000000L))return R.err("invalid bit rate");
        jdbc.update("INSERT INTO engine_bandwidth_group(node_id,scope,owner_id,up_bits,down_bits,updated_at) VALUES(?,?,?,?,?,?) ON DUPLICATE KEY UPDATE up_bits=VALUES(up_bits),down_bits=VALUES(down_bits),updated_at=VALUES(updated_at)",node,scope,owner,up,down,System.currentTimeMillis());engine.limiterChanged(node);credentials.audit(JwtUtil.getUserIdFromToken().longValue(),node,"SET_BANDWIDTH_GROUP",null,scope+":"+owner);return R.ok();
    }
    private static long exactRate(JSONObject input,String key){Object value=input.get(key);return value==null?0:new java.math.BigDecimal(value.toString()).longValueExact();}
    @PostMapping("/audit") @RequireRole
    public R audit(@RequestBody JSONObject input){int limit=Math.max(1,Math.min(200,input.getIntValue("limit")));return R.ok(jdbc.queryForList("SELECT id,created_at createdAt,user_id userId,node_id nodeId,action,service_id serviceId,detail FROM engine_audit WHERE node_id=? ORDER BY id DESC LIMIT ?",input.getLong("nodeId"),limit));}
}
