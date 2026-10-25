package com.admin.controller;

import com.admin.common.engine.EngineTrafficService;
import com.admin.entity.Node;
import com.admin.mapper.NodeMapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.alibaba.fastjson.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import javax.annotation.Resource;

@RestController
@RequestMapping("/flow/engine/v1")
public class EngineTrafficController {
    @Resource private NodeMapper nodes;
    @Resource private EngineTrafficService traffic;
    @PostMapping("/traffic")
    public String traffic(@RequestHeader("Authorization") String authorization,@RequestBody JSONObject report) {
        if(!authorization.startsWith("Bearer ")) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        Node n=nodes.selectOne(new QueryWrapper<Node>().eq("secret",authorization.substring(7)));
        if(n==null || !"iptables".equals(n.getEngine())) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        try {traffic.ingest(n,report);return "ok";}catch(IllegalArgumentException e){throw new ResponseStatusException(HttpStatus.BAD_REQUEST,e.getMessage());}
    }
}
