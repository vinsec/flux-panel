package com.admin.common.engine;

import com.admin.common.dto.GostDto;

public interface ForwardingEngine {
    GostDto apply(Long nodeId, ForwardSpec spec, boolean update);
    GostDto delete(Long nodeId, String name);
    GostDto setEnabled(Long nodeId, String name, boolean enabled);
}
