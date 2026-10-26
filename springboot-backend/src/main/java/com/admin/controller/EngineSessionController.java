package com.admin.controller;

import com.admin.common.annotation.RequireRole;
import com.admin.common.engine.NodeCredentials;
import com.admin.common.lang.R;
import com.admin.common.utils.JwtUtil;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import javax.annotation.Resource;

@RestController
public class EngineSessionController {
    @Resource private NodeCredentials credentials;
    @PostMapping("/flow/engine/v3/session")
    public JSONObject issue(@RequestHeader("Authorization")String authorization){try{return credentials.issue(authorization);}catch(IllegalArgumentException error){throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,"invalid node authentication");}}
    @PostMapping("/api/v1/engine/socket-ticket") @RequireRole
    public R ticket(@RequestHeader("Authorization")String token){return R.ok(credentials.ticket(JwtUtil.getUserIdFromToken(token)));}
    @PostMapping("/api/v1/engine/revoke-sessions") @RequireRole
    public R revoke(@RequestHeader("Authorization")String token,@RequestBody JSONObject data){credentials.revoke(data.getLongValue("nodeId"),JwtUtil.getUserIdFromToken(token));return R.ok();}
}
