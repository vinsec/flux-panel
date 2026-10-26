package com.admin.controller;

import com.admin.common.engine.EngineCreditService;
import com.admin.common.engine.EngineTrafficService;
import com.admin.entity.Node;
import com.admin.mapper.NodeMapper;
import com.alibaba.fastjson.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.annotation.Resource;

@RestController
@RequestMapping("/flow/engine")
public class EngineTrafficController {
    @Resource private NodeMapper nodes;
    @Resource private EngineTrafficService traffic;
    @Resource private EngineCreditService credits;
    @Resource private com.admin.common.engine.NodeCredentials credentials;

    @PostMapping("/v1/traffic")
    public String traffic(
            @RequestHeader("Authorization") String authorization, @RequestBody JSONObject report) {
        if (!authorization.startsWith("Bearer "))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        var identity=credentials.bearer(authorization);
        Node n = identity==null?null:identity.node();
        if (n == null || !"iptables".equals(n.getEngine()))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        if (credits.strict(n.getId()))
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT, "strict credit nodes require v2 reporting");
        try {
            traffic.ingest(n, report);
            return "ok";
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/v2/traffic")
    public JSONObject trafficV2(
            @RequestHeader("Authorization") String authorization, @RequestBody JSONObject report) {
        if (!authorization.startsWith("Bearer "))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        var identity=credentials.bearer(authorization);
        Node n = identity==null?null:identity.node();
        if (n == null || !"iptables".equals(n.getEngine()))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        try {
            return credits.exchange(n, report);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }

    @PostMapping("/v2/maintenance")
    public JSONObject maintenance(
            @RequestHeader("Authorization") String authorization, @RequestBody JSONObject report) {
        if (!authorization.startsWith("Bearer "))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        var identity=credentials.bearer(authorization);
        Node n = identity==null?null:identity.node();
        if (n == null || !"iptables".equals(n.getEngine()))
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        try {
            return credits.maintenance(n, report);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }
}
