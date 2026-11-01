package com.admin.common.engine;

import com.admin.entity.Node;
import com.admin.mapper.NodeMapper;
import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.scheduling.annotation.Scheduled;
import javax.annotation.Resource;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Short lived opaque node access; the bootstrap credential stays off URLs. */
@Service
public class NodeCredentials {
    public record Identity(Node node,long expiresAt){}
    private record Ticket(long user,long expiry){}
    @Resource private NodeMapper nodes;
    @Resource private JdbcTemplate jdbc;
    @Value("${engine.auth.session-millis:900000}") private long lifetime;
    @Value("${engine.auth.allow-legacy-query:true}") private boolean legacyQuery;
    private final SecureRandom random=new SecureRandom();
    private final ConcurrentHashMap<String,Ticket> tickets=new ConcurrentHashMap<>();
    public static String hash(String value){try{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));}catch(Exception e){throw new IllegalStateException(e);}}
    private String token(){byte[] data=new byte[32];random.nextBytes(data);return HexFormat.of().formatHex(data);}
    public boolean legacyQueryAllowed(){return legacyQuery;}
    public Identity resolve(String value){
        if(value==null||value.length()>256)return null;
        if(value.matches("[a-f0-9]{64}")){
            var rows=jdbc.queryForList("SELECT node_id,expires_at FROM engine_session WHERE token_hash=? AND expires_at>?",hash(value),System.currentTimeMillis());
            if(!rows.isEmpty()){var row=rows.get(0);Node node=nodes.selectById(((Number)row.get("node_id")).longValue());if(node!=null)return new Identity(node,((Number)row.get("expires_at")).longValue());}
        }
        Node node=nodes.selectOne(new QueryWrapper<Node>().eq("secret",value));
        return node==null?null:new Identity(node,0);
    }
    public Identity bearer(String authorization){if(authorization==null||!authorization.startsWith("Bearer "))return null;return resolve(authorization.substring(7));}
    public JSONObject issue(String authorization){
        if(authorization==null||!authorization.startsWith("Bearer "))throw new IllegalArgumentException("bootstrap authentication required");
        String value=authorization.substring(7);if(value.length()>128)throw new IllegalArgumentException("invalid bootstrap credential");
        Node node=nodes.selectOne(new QueryWrapper<Node>().eq("secret",value));
        if(node==null||!"kernel".equals(node.getEngine()))throw new IllegalArgumentException("invalid bootstrap credential");
        KernelBackend.forNode(node);
        long now=System.currentTimeMillis(),expires=now+Math.max(60000,Math.min(3600000,lifetime));String access=token();
        jdbc.update("INSERT INTO engine_session(token_hash,node_id,created_at,expires_at) VALUES(?,?,?,?)",hash(access),node.getId(),now,expires);
        JSONObject result=new JSONObject();result.put("accessToken",access);result.put("expiresAt",expires);result.put("validForMillis",expires-now);result.put("nodeId",node.getId());return result;
    }
    public void revoke(long node,long user){jdbc.update("DELETE FROM engine_session WHERE node_id=?",node);com.admin.common.utils.WebSocketServer.revokeNodeSession(node);audit(user,node,"REVOKE_NODE_SESSIONS",null,"short lived sessions revoked");}
    public JSONObject ticket(long user){if(tickets.size()>4096)throw new IllegalStateException("ticket capacity exceeded");String value=token();tickets.put(hash(value),new Ticket(user,System.currentTimeMillis()+30000));JSONObject result=new JSONObject();result.put("ticket",value);result.put("expiresInMillis",30000);return result;}
    public Long consumeTicket(String value){if(value==null||value.length()!=64)return null;Ticket ticket=tickets.remove(hash(value));return ticket!=null&&ticket.expiry()>System.currentTimeMillis()?ticket.user():null;}
    public void audit(Long user,Long node,String action,String service,String detail){String safe=LogRedaction.redactText(detail);jdbc.update("INSERT INTO engine_audit(created_at,user_id,node_id,action,service_id,detail) VALUES(?,?,?,?,?,?)",System.currentTimeMillis(),user,node,action,service,safe.substring(0,Math.min(2048,safe.length())));}
    @Scheduled(fixedDelay=5000,initialDelay=5000)
    public void expire(){long now=System.currentTimeMillis();tickets.entrySet().removeIf(e->e.getValue().expiry()<now);jdbc.update("DELETE FROM engine_session WHERE expires_at<?",now-60000);com.admin.common.utils.WebSocketServer.closeExpiredNodeSessions(now);}
}
