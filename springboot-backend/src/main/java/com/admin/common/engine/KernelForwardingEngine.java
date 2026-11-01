package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.admin.entity.User;
import com.admin.entity.UserTunnel;
import com.admin.mapper.NodeMapper;
import com.admin.mapper.UserMapper;
import com.admin.mapper.UserTunnelMapper;
import com.alibaba.fastjson.JSONObject;

import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

@Component
public class KernelForwardingEngine implements ForwardingEngine {
    @Resource private EngineRevision revisions;
    @Resource private UserMapper users;
    @Resource private UserTunnelMapper userTunnels;
    @Resource private NodeMapper nodes;
    @Resource @Lazy private EngineTrafficService traffic;
    @Resource private EngineCreditService credits;
    @Resource private EngineCreditPrimer primer;
    @Resource private EngineQuotaModeGuard quotaModes;
    @Resource private EngineSpecFactory specs;
    @Resource private NodeCredentials credentials;
    @Resource @Lazy private EngineBatchReconciler batches;
    private final java.util.Set<Long> limiterQueue=java.util.concurrent.ConcurrentHashMap.newKeySet();

    public static boolean ipv4(String value) {
        if (value == null || !value.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
        for (String p : value.split("\\."))
            if (Integer.parseInt(p) > 255 || (p.length() > 1 && p.startsWith("0"))) return false;
        return true;
    }

    public static void validate(ForwardSpec s) {
        if (s.getTunnelType() != 1)
            throw new IllegalArgumentException("kernel schema1 only supports direct port forwarding");
        if (s.getLimiter() != null && s.getLimiter() != 0)
            throw new IllegalArgumentException("kernel schema1 does not support bandwidth shaping");
        if (s.getInterfaceName() != null && !s.getInterfaceName().isBlank())
            throw new IllegalArgumentException("kernel schema1 does not support interface routing");
        if (s.getStrategy() != null
                && !s.getStrategy().isBlank()
                && !s.getStrategy().equals("fifo"))
            throw new IllegalArgumentException("kernel schema1 only supports one target");
        Endpoint target = Endpoint.parse(s.getTarget());
        if (!"ip".equals(target.getKind()) || !"ipv4".equals(target.getFamily()))
            throw new IllegalArgumentException(
                    "node currently supports IPv4 targets; DNS/IPv6 capabilities are disabled");
        String ip = s.getTunnel().getTcpListenAddr();
        if (!ipv4(ip) || !ip.equals(s.getTunnel().getUdpListenAddr()))
            throw new IllegalArgumentException(
                    "kernel schema1 requires identical IPv4 TCP/UDP listen addresses");
        if (!"kernel".equals(EngineRegistry.normalize(s.getTunnel().getEngine())))
            throw new IllegalArgumentException("node and tunnel engine mismatch");
    }

    public GostDto apply(Long node, ForwardSpec s, boolean update) {
        try {
            if(s.getTunnelType()!=1||!"kernel".equals(EngineRegistry.normalize(s.getTunnel().getEngine())))throw new IllegalArgumentException("kernel supports direct forwarding on a matching node");
            EngineCapabilities.negotiate(node);
            KernelBackend.verifyAgent(nodes.selectById(node), EngineCapabilities.info(node));
            quotaModes.verify(node,s.getName());
            JSONObject d=specs.advanced(node,s);
            if(d==null){
                validate(s);Endpoint target=Endpoint.parse(s.getTarget());d=new JSONObject();d.put("listenIP",s.getTunnel().getTcpListenAddr());d.put("listenPort",s.getPort());d.put("targetIP",target.getHost());d.put("targetPort",target.getPort());
                if(EngineCapabilities.supports(node,"structuredEndpoint")){d.put("schemaVersion",2);d.put("listen",Endpoint.parse(EngineSpecFactory.join(s.getTunnel().getTcpListenAddr(),s.getPort())).json());d.put("target",target.json());d.put("protocols",java.util.List.of("tcp","udp"));}
            }
            d.put("id",s.getName());d.put("revision",revisions.next(node,s.getName()));d.put("enabled",!Boolean.FALSE.equals(s.getEnabled()));
            String[] ids=s.getName().split("_");long expires=0;
            if(ids.length==3&&!ids[2].equals("0")){User user=users.selectById(ids[1]);UserTunnel permission=userTunnels.selectById(ids[2]);if(user!=null&&user.getExpTime()!=null)expires=user.getExpTime();if(permission!=null&&permission.getExpTime()!=null&&(expires==0||permission.getExpTime()<expires))expires=permission.getExpTime();}
            d.put("expiresAt",expires);
            if(ids.length==3&&!ids[2].equals("0")&&(EngineCapabilities.supports(node,"creditLease")||credits.strict(node))){EngineCapabilities.require(node,"creditLease");credits.enable(node);d.put("leaseRequired",true);}
            GostDto result=WebSocketServer.send_msg(node,d,"ApplyForward");
            if("OK".equals(result.getMsg())){credentials.audit(null,node,update?"UPDATE_FORWARD":"CREATE_FORWARD",s.getName(),"revision="+d.getLongValue("revision"));if(d.getBooleanValue("leaseRequired"))primer.afterCommit(node,s.getName());}
            return result;
        }catch(Exception e){return error(LogRedaction.redactText(e.getMessage()));}
    }
    public GostDto limiterChanged(Long node){
        if(!EngineCapabilities.supports(node,"shaping"))return error("node does not advertise shaping");
        return queueDefinitionChange(node);
    }
    public GostDto protocolChanged(Long node){return queueDefinitionChange(node);}
    private GostDto queueDefinitionChange(Long node){
        Runnable enqueue=()->{specs.invalidate(node);limiterQueue.add(node);};
        if(org.springframework.transaction.support.TransactionSynchronizationManager.isSynchronizationActive())org.springframework.transaction.support.TransactionSynchronizationManager.registerSynchronization(new org.springframework.transaction.support.TransactionSynchronization(){public void afterCommit(){enqueue.run();}});else enqueue.run();
        GostDto result=new GostDto();result.setMsg("OK");return result;
    }
    @org.springframework.scheduling.annotation.Scheduled(fixedDelay=1000,initialDelay=1000)
    public void applyLimiterDefinitions(){for(Long node:new java.util.ArrayList<>(limiterQueue)){limiterQueue.remove(node);try{batches.reconcile(node);}catch(Exception error){limiterQueue.add(node);}break;}}

    public GostDto delete(Long node, String name) {
        GostDto result = command(node, name, false, "DeleteForward");
        if ("OK".equals(result.getMsg()) && result.getData() != null) {
            try {
                traffic.ingest(
                        nodes.selectById(node), (JSONObject) JSONObject.toJSON(result.getData()));
            } catch (Exception e) {
                return error("final usage settlement failed: " + e.getMessage());
            }
        }
        return result;
    }

    public GostDto setEnabled(Long node, String name, boolean enabled) {
        return command(node, name, enabled, "SetForwardState");
    }

    private GostDto command(Long node, String name, boolean enabled, String command) {
        try {
            EngineCapabilities.negotiate(node);
            KernelBackend.verifyAgent(nodes.selectById(node), EngineCapabilities.info(node));
            if (enabled) quotaModes.verify(node, name);
            if (enabled && credits.strict(node)) EngineCapabilities.require(node, "creditLease");
            JSONObject d = new JSONObject();
            d.put("id", name);
            d.put("revision", revisions.next(node, name));
            d.put("enabled", enabled);
            GostDto result = WebSocketServer.send_msg(node, d, command);
            if (enabled && "OK".equals(result.getMsg()) && !name.endsWith("_0"))
                primer.afterCommit(node, name);
            return result;
        } catch (Exception e) {
            return error(e.getMessage());
        }
    }

    public static GostDto error(String msg) {
        GostDto r = new GostDto();
        r.setMsg(msg);
        return r;
    }
}
