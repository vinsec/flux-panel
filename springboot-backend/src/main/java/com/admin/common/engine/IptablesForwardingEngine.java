package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.admin.entity.User;
import com.admin.entity.UserTunnel;
import com.admin.mapper.UserMapper;
import com.admin.mapper.UserTunnelMapper;
import com.alibaba.fastjson.JSONObject;
import org.springframework.stereotype.Component;
import org.springframework.context.annotation.Lazy;
import com.admin.mapper.NodeMapper;
import javax.annotation.Resource;

@Component
public class IptablesForwardingEngine implements ForwardingEngine {
    @Resource private EngineRevision revisions;
    @Resource private UserMapper users;
    @Resource private UserTunnelMapper userTunnels;
    @Resource private NodeMapper nodes;
    @Resource @Lazy private EngineTrafficService traffic;

    public static boolean ipv4(String value) {
        if (value==null || !value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
        for(String p:value.split("\\.")) if(Integer.parseInt(p)>255 || (p.length()>1 && p.startsWith("0"))) return false;
        return true;
    }
    public static void validate(ForwardSpec s) {
        if(s.getTunnelType()!=1) throw new IllegalArgumentException("iptables v1 only supports direct port forwarding");
        if(s.getLimiter()!=null && s.getLimiter()!=0) throw new IllegalArgumentException("iptables v1 does not support bandwidth shaping");
        if(s.getInterfaceName()!=null && !s.getInterfaceName().isBlank()) throw new IllegalArgumentException("iptables v1 does not support interface routing");
        if(s.getStrategy()!=null && !s.getStrategy().isBlank() && !s.getStrategy().equals("fifo")) throw new IllegalArgumentException("iptables v1 only supports one target");
        String[] target=s.getTarget().split(":",-1);
        if(target.length!=2 || !ipv4(target[0]) || !target[1].matches("[0-9]{1,5}") || Integer.parseInt(target[1])<1 || Integer.parseInt(target[1])>65535) throw new IllegalArgumentException("iptables v1 requires a single IPv4:port target");
        String ip=s.getTunnel().getTcpListenAddr();
        if(!ipv4(ip) || !ip.equals(s.getTunnel().getUdpListenAddr())) throw new IllegalArgumentException("iptables v1 requires identical IPv4 TCP/UDP listen addresses");
        if(!"iptables".equals(EngineRegistry.normalize(s.getTunnel().getEngine()))) throw new IllegalArgumentException("node and tunnel engine mismatch");
    }
    public GostDto apply(Long node,ForwardSpec s,boolean update) {
        try {
            validate(s);String[] target=s.getTarget().split(":");
            JSONObject d=new JSONObject();d.put("id",s.getName());d.put("revision",revisions.next(node,s.getName()));
            d.put("listenIP",s.getTunnel().getTcpListenAddr());d.put("listenPort",s.getPort());d.put("targetIP",target[0]);d.put("targetPort",Integer.parseInt(target[1]));d.put("enabled",!Boolean.FALSE.equals(s.getEnabled()));
            String[] ids=s.getName().split("_");long expires=0;
            if(ids.length==3 && !ids[2].equals("0")) {
                User u=users.selectById(ids[1]);UserTunnel ut=userTunnels.selectById(ids[2]);
                if(u!=null && u.getExpTime()!=null) expires=u.getExpTime();
                if(ut!=null && ut.getExpTime()!=null && (expires==0 || ut.getExpTime()<expires)) expires=ut.getExpTime();
            }
            d.put("expiresAt",expires);return WebSocketServer.send_msg(node,d,"ApplyForward");
        } catch(Exception e) {return error(e.getMessage());}
    }
    public GostDto delete(Long node,String name) {
        GostDto result=command(node,name,false,"DeleteForward");
        if("OK".equals(result.getMsg()) && result.getData()!=null) {
            try {traffic.ingest(nodes.selectById(node),(JSONObject)JSONObject.toJSON(result.getData()));}
            catch(Exception e){return error("final usage settlement failed: "+e.getMessage());}
        }
        return result;
    }
    public GostDto setEnabled(Long node,String name,boolean enabled) {return command(node,name,enabled,"SetForwardState");}
    private GostDto command(Long node,String name,boolean enabled,String command) {
        try {JSONObject d=new JSONObject();d.put("id",name);d.put("revision",revisions.next(node,name));d.put("enabled",enabled);return WebSocketServer.send_msg(node,d,command);}
        catch(Exception e){return error(e.getMessage());}
    }
    public static GostDto error(String msg){GostDto r=new GostDto();r.setMsg(msg);return r;}
}
