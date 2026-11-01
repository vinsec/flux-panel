package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.LegacyGostCommands;

import org.springframework.stereotype.Component;

@Component
public class GostForwardingEngine implements ForwardingEngine {
    @javax.annotation.Resource private EngineQuotaModeGuard quotaModes;

    public GostDto apply(Long n, ForwardSpec s, boolean update) {
        try {
            quotaModes.verify(n, s.getName());
        } catch (IllegalArgumentException e) {
            return KernelForwardingEngine.error(e.getMessage());
        }
        return update
                ? LegacyGostCommands.UpdateService(
                        n,
                        s.getName(),
                        s.getPort(),
                        s.getLimiter(),
                        s.getTarget(),
                        s.getTunnelType(),
                        s.getTunnel(),
                        s.getStrategy(),
                        s.getInterfaceName())
                : LegacyGostCommands.AddService(
                        n,
                        s.getName(),
                        s.getPort(),
                        s.getLimiter(),
                        s.getTarget(),
                        s.getTunnelType(),
                        s.getTunnel(),
                        s.getStrategy(),
                        s.getInterfaceName());
    }

    public GostDto delete(Long n, String name) {
        return LegacyGostCommands.DeleteService(n, name);
    }

    public GostDto setEnabled(Long n, String name, boolean enabled) {
        if (enabled) {
            try {
                quotaModes.verify(n, name);
            } catch (IllegalArgumentException e) {
                return KernelForwardingEngine.error(e.getMessage());
            }
        }
        return enabled
                ? LegacyGostCommands.ResumeService(n, name)
                : LegacyGostCommands.PauseService(n, name);
    }
}
