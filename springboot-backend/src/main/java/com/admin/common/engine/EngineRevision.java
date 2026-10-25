package com.admin.common.engine;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.annotation.Resource;

@Service
public class EngineRevision {
    @Resource private JdbcTemplate jdbc;
    @Transactional
    public long next(Long node,String name) {
        jdbc.update("INSERT IGNORE INTO engine_revision(node_id,service_id,revision) VALUES(?,?,0)",node,name);
        Long v=jdbc.queryForObject("SELECT revision FROM engine_revision WHERE node_id=? AND service_id=? FOR UPDATE",Long.class,node,name);
        jdbc.update("UPDATE engine_revision SET revision=? WHERE node_id=? AND service_id=?",v+1,node,name);
        return v+1;
    }
}
