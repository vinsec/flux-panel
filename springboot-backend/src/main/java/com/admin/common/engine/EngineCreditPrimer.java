package com.admin.common.engine;

import com.admin.common.dto.GostDto;
import com.admin.common.utils.WebSocketServer;
import com.admin.entity.Node;
import com.admin.mapper.NodeMapper;
import com.alibaba.fastjson.JSONObject;

import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import javax.annotation.Resource;

/**
 * Allocate first credit only AFTER the forwarding DB transaction is visible. Waiting for the node's
 * HTTP poll inside that transaction would deadlock or make the first connection race an uncommitted
 * forwarding row.
 */
@Service
public class EngineCreditPrimer {
    @Resource private EngineCreditService credits;
    @Resource private NodeMapper nodes;

    public void afterCommit(Long node, String service) {
        if (!EngineCapabilities.supports(node, "creditPush")) return;
        Runnable allocate =
                () -> {
                    try {
                        Node identity = nodes.selectById(node);
                        if (identity == null) return;
                        for (int attempt = 0; attempt < 3; attempt++) {
                            GostDto request =
                                    WebSocketServer.send_msg(
                                            node, new JSONObject(), "RequestCredit");
                            if (!"OK".equals(request.getMsg()) || request.getData() == null) return;
                            JSONObject report = (JSONObject) JSONObject.toJSON(request.getData());
                            JSONObject ack = credits.exchangeNew(identity, report);
                            ack.put("serviceId", service);
                            GostDto installed =
                                    WebSocketServer.send_msg(node, ack, "InstallCredit");
                            if (!"OK".equals(installed.getMsg())) return;
                            JSONObject info = (JSONObject) JSONObject.toJSON(installed.getData());
                            if (info != null && info.getBooleanValue("ready")) return;
                        }
                    } catch (Exception error) {
                        /* Periodic acknowledged reporting retries safely. */
                    }
                };
        if (TransactionSynchronizationManager.isSynchronizationActive())
            TransactionSynchronizationManager.registerSynchronization(
                    new TransactionSynchronization() {
                        public void afterCommit() {
                            allocate.run();
                        }
                    });
        else allocate.run();
    }
}
