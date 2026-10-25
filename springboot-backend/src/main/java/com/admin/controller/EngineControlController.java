package com.admin.controller;

import com.admin.common.annotation.RequireRole;
import com.admin.common.dto.GostDto;
import com.admin.common.engine.*;
import com.admin.common.lang.R;
import com.admin.common.utils.WebSocketServer;
import com.alibaba.fastjson.JSONObject;

import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;

/** Administrative inspection and DB-driven reconciliation, never arbitrary RPC. */
@RestController
@RequestMapping("/api/v1/engine")
public class EngineControlController {
    @Resource private EngineBatchReconciler batches;

    @PostMapping("/capabilities")
    @RequireRole
    public R capabilities(@RequestBody JSONObject data) {
        JSONObject info = EngineCapabilities.negotiate(data.getLong("nodeId"));
        return info == null ? R.err("node capabilities unavailable") : R.ok(info);
    }

    @PostMapping("/reconcile")
    @RequireRole
    public R reconcile(@RequestBody JSONObject data) {
        try {
            return R.ok(batches.reconcile(data.getLong("nodeId")));
        } catch (Exception e) {
            return R.err(e.getMessage());
        }
    }

    @PostMapping("/batch-status")
    @RequireRole
    public R status(@RequestBody JSONObject data) {
        JSONObject query = new JSONObject();
        query.put("id", data.getString("id"));
        GostDto result = WebSocketServer.send_msg(data.getLong("nodeId"), query, "GetBatchStatus");
        return "OK".equals(result.getMsg()) ? R.ok(result.getData()) : R.err(result.getMsg());
    }

    @PostMapping("/collect")
    @RequireRole
    public R collect(@RequestBody JSONObject data) {
        GostDto result =
                WebSocketServer.send_msg(
                        data.getLong("nodeId"), new JSONObject(), "CollectCounters");
        return "OK".equals(result.getMsg()) ? R.ok(result.getData()) : R.err(result.getMsg());
    }
}
