package com.admin.common.utils;

import com.admin.common.dto.GostDto;
import com.admin.entity.Tunnel;
import com.admin.common.engine.*;

/** Backward-compatible facade: every lifecycle path selects a forwarding engine. */
public class GostUtil {
    public static GostDto AddLimiters(Long node_id, Long name, String speed) {
        if(EngineRegistry.isKernel(node_id)) return ((KernelForwardingEngine)EngineRegistry.forNode(node_id)).limiterChanged(node_id);
        return LegacyGostCommands.AddLimiters(node_id,name,speed);
    }
    public static GostDto UpdateLimiters(Long node_id, Long name, String speed) {
        if(EngineRegistry.isKernel(node_id)) return ((KernelForwardingEngine)EngineRegistry.forNode(node_id)).limiterChanged(node_id);
        return LegacyGostCommands.UpdateLimiters(node_id,name,speed);
    }
    public static GostDto DeleteLimiters(Long node_id, Long name) {
        if(EngineRegistry.isKernel(node_id)) return ((KernelForwardingEngine)EngineRegistry.forNode(node_id)).limiterChanged(node_id);
        return LegacyGostCommands.DeleteLimiters(node_id,name);
    }
    public static GostDto AddService(Long node_id, String name, Integer in_port, Integer limiter, String remoteAddr, Integer fow_type, Tunnel tunnel, String strategy, String interfaceName) {
        return EngineRegistry.forNode(node_id).apply(node_id,new ForwardSpec(name,in_port,limiter,remoteAddr,fow_type,tunnel,strategy,interfaceName),false);
    }
    public static GostDto UpdateService(Long node_id, String name, Integer in_port, Integer limiter, String remoteAddr, Integer fow_type, Tunnel tunnel, String strategy, String interfaceName) {
        return EngineRegistry.forNode(node_id).apply(node_id,new ForwardSpec(name,in_port,limiter,remoteAddr,fow_type,tunnel,strategy,interfaceName),true);
    }
    public static GostDto ApplyServiceOptions(Long node,String name,Integer port,Integer limiter,String target,Integer type,Tunnel tunnel,String strategy,String iface,String options,boolean update){ForwardSpec spec=new ForwardSpec(name,port,limiter,target,type,tunnel,strategy,iface);spec.setEngineOptions(options);return EngineRegistry.forNode(node).apply(node,spec,update);}
    public static GostDto DeleteService(Long node_id, String name) {
        return EngineRegistry.forNode(node_id).delete(node_id,name);
    }
    public static GostDto AddRemoteService(Long node_id, String name, Integer out_port, String remoteAddr,  String protocol, String strategy, String interfaceName) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support AddRemoteService");
        return LegacyGostCommands.AddRemoteService(node_id,name,out_port,remoteAddr,protocol,strategy,interfaceName);
    }
    public static GostDto UpdateRemoteService(Long node_id, String name, Integer out_port, String remoteAddr,String protocol, String strategy, String interfaceName) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support UpdateRemoteService");
        return LegacyGostCommands.UpdateRemoteService(node_id,name,out_port,remoteAddr,protocol,strategy,interfaceName);
    }
    public static GostDto DeleteRemoteService(Long node_id, String name) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support DeleteRemoteService");
        return LegacyGostCommands.DeleteRemoteService(node_id,name);
    }
    public static GostDto PauseService(Long node_id, String name) {
        return EngineRegistry.forNode(node_id).setEnabled(node_id,name,false);
    }
    public static GostDto ResumeService(Long node_id, String name) {
        return EngineRegistry.forNode(node_id).setEnabled(node_id,name,true);
    }
    public static GostDto PauseRemoteService(Long node_id, String name) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support PauseRemoteService");
        return LegacyGostCommands.PauseRemoteService(node_id,name);
    }
    public static GostDto ResumeRemoteService(Long node_id, String name) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support ResumeRemoteService");
        return LegacyGostCommands.ResumeRemoteService(node_id,name);
    }
    public static GostDto AddChains(Long node_id, String name, String remoteAddr, String protocol, String interfaceName) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support AddChains");
        return LegacyGostCommands.AddChains(node_id,name,remoteAddr,protocol,interfaceName);
    }
    public static GostDto UpdateChains(Long node_id, String name, String remoteAddr, String protocol, String interfaceName) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support UpdateChains");
        return LegacyGostCommands.UpdateChains(node_id,name,remoteAddr,protocol,interfaceName);
    }
    public static GostDto DeleteChains(Long node_id, String name) {
        if(EngineRegistry.isKernel(node_id)) return KernelForwardingEngine.error("iptables v1 does not support DeleteChains");
        return LegacyGostCommands.DeleteChains(node_id,name);
    }
}
