package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.admin.entity.*;
import com.admin.mapper.*;
import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;
import javax.annotation.Resource;
import java.util.*;

/** Reconcile desired business state after disconnects, force-delete or lost state. */
@Component @Slf4j
public class EngineReconciler {
    @Resource private NodeMapper nodes;
    @Resource private TunnelMapper tunnels;
    @Resource private ForwardMapper forwards;
    @Resource private UserMapper users;
    @Resource private UserTunnelMapper permissions;
    @Resource private IptablesForwardingEngine engine;

    @Scheduled(fixedDelay=30000,initialDelay=10000)
    public void reconcile() {
        for(Node n:nodes.selectList(new QueryWrapper<Node>().eq("engine","iptables").eq("status",1))) {
            try {reconcile(n);}catch(Exception e){log.warn("iptables node {} reconciliation failed: {}",n.getId(),e.getMessage());}
        }
    }
    private void reconcile(Node n) {
        GostDto snapshot=WebSocketServer.send_msg(n.getId(),new JSONObject(),"GetEngineState");
        if(!"OK".equals(snapshot.getMsg()) || snapshot.getData()==null) return;
        JSONObject actual=(JSONObject)JSONObject.toJSON(snapshot.getData());Set<String> expected=new HashSet<>();
        for(Tunnel t:tunnels.selectList(new QueryWrapper<Tunnel>().eq("in_node_id",n.getId()).eq("engine","iptables"))) {
            for(Forward f:forwards.selectList(new QueryWrapper<Forward>().eq("tunnel_id",t.getId()))) {
                User u=users.selectById(f.getUserId());if(u==null)continue;
                UserTunnel p=permissions.selectOne(new QueryWrapper<UserTunnel>().eq("user_id",f.getUserId()).eq("tunnel_id",t.getId()));
                if(u.getRoleId()!=0 && p==null)continue;
                if(u.getRoleId()==0)p=null;
                String id=f.getId()+"_"+f.getUserId()+"_"+(p==null?"0":p.getId());expected.add(id);
                JSONObject observed=actual.getJSONObject(id);
                boolean enabled=Objects.equals(f.getStatus(),1) && Objects.equals(u.getStatus(),1) && (u.getExpTime()==null || u.getExpTime()>System.currentTimeMillis()) && (p==null || (Objects.equals(p.getStatus(),1) && p.getExpTime()>System.currentTimeMillis()));
                long expires=p==null?0:Math.min(u.getExpTime()==null?Long.MAX_VALUE:u.getExpTime(),p.getExpTime());
                String[] target=f.getRemoteAddr().split(":");
                boolean changed=observed==null || observed.getBooleanValue("deleted") || target.length!=2 || !target[0].equals(observed.getString("targetIP")) || !Objects.equals(Integer.valueOf(target[1]),observed.getInteger("targetPort")) || !Objects.equals(f.getInPort(),observed.getInteger("listenPort")) || !t.getTcpListenAddr().equals(observed.getString("listenIP")) || expires!=observed.getLongValue("expiresAt");
                if(changed) {
                    ForwardSpec request=new ForwardSpec(id,f.getInPort(),p==null?null:p.getSpeedId(),f.getRemoteAddr(),t.getType(),t,f.getStrategy(),f.getInterfaceName());request.setEnabled(enabled);
                    GostDto result=engine.apply(n.getId(),request,true);
                    if(!"OK".equals(result.getMsg()))continue;
                }
                if(!changed && enabled!=observed.getBooleanValue("enabled")) {
                    GostDto result=engine.setEnabled(n.getId(),id,enabled);
                    if(!enabled && "OK".equals(result.getMsg()) && !Objects.equals(f.getStatus(),0)){f.setStatus(0);forwards.updateById(f);}
                }
            }
        }
        for(String id:actual.keySet())if(!expected.contains(id) && !actual.getJSONObject(id).getBooleanValue("deleted"))engine.delete(n.getId(),id);
    }
}
