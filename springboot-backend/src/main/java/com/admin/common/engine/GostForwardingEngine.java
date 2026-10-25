package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.LegacyGostCommands;
import org.springframework.stereotype.Component;

@Component
public class GostForwardingEngine implements ForwardingEngine {
    public GostDto apply(Long n, ForwardSpec s, boolean update) {
        return update ? LegacyGostCommands.UpdateService(n,s.getName(),s.getPort(),s.getLimiter(),s.getTarget(),s.getTunnelType(),s.getTunnel(),s.getStrategy(),s.getInterfaceName())
                : LegacyGostCommands.AddService(n,s.getName(),s.getPort(),s.getLimiter(),s.getTarget(),s.getTunnelType(),s.getTunnel(),s.getStrategy(),s.getInterfaceName());
    }
    public GostDto delete(Long n,String name) { return LegacyGostCommands.DeleteService(n,name); }
    public GostDto setEnabled(Long n,String name,boolean enabled) { return enabled ? LegacyGostCommands.ResumeService(n,name) : LegacyGostCommands.PauseService(n,name); }
}
