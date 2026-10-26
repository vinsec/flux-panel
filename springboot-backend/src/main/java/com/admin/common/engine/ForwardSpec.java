package com.admin.common.engine;

import com.admin.entity.Tunnel;
import lombok.Data;

/** Engine-neutral business request; protocol JSON belongs to an adapter. */
@Data
public class ForwardSpec {
    public ForwardSpec(String name,Integer port,Integer limiter,String target,Integer tunnelType,Tunnel tunnel,String strategy,String interfaceName) {
        this.name=name;this.port=port;this.limiter=limiter;this.target=target;this.tunnelType=tunnelType;this.tunnel=tunnel;this.strategy=strategy;this.interfaceName=interfaceName;
    }
    private Boolean enabled = true;
    private String engineOptions;
    private String name;
    private Integer port;
    private Integer limiter;
    private String target;
    private Integer tunnelType;
    private Tunnel tunnel;
    private String strategy;
    private String interfaceName;
}
