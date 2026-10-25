package com.admin.common.engine;

import com.admin.common.dto.FlowDto;
import com.admin.controller.FlowController;
import com.admin.entity.Forward;
import com.admin.entity.Node;
import com.admin.entity.Tunnel;
import com.admin.mapper.ForwardMapper;
import com.admin.mapper.TunnelMapper;
import com.admin.mapper.UserTunnelMapper;
import com.admin.entity.UserTunnel;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import javax.annotation.Resource;
import java.util.Map;

@Service
public class EngineTrafficService {
    @Resource private JdbcTemplate jdbc;
    @Resource private ForwardMapper forwards;
    @Resource private TunnelMapper tunnels;
    @Resource private UserTunnelMapper userTunnels;
    @Resource private FlowController flow;

    @Transactional
    public void ingest(Node node,JSONObject report) {
        String epoch=report.getString("epoch");long seq=report.getLongValue("sequence");JSONArray usage=report.getJSONArray("usage");
        if(epoch==null || !epoch.matches("[a-f0-9]{32}") || seq<1 || usage==null || usage.size()>10000) throw new IllegalArgumentException("invalid usage report");
        for(int i=0;i<usage.size();i++) {
            JSONObject u=usage.getJSONObject(i);String name=u.getString("id");
            if(name==null || !name.matches("[0-9]+_[0-9]+_[0-9]+") || name.length()>100) throw new IllegalArgumentException("invalid service id");
            String[] ids=name.split("_");Forward f=forwards.selectById(ids[0]);
            // A deleted forwarding's final snapshot may arrive after its DB row.
            if(f==null) continue;
            Tunnel t=tunnels.selectById(f.getTunnelId());
            // Retired/migrated forwards may remain in a durable agent outbox.
            // Never credit a different owner; acknowledge stale records so they
            // cannot prevent all other forwards in the batch from settling.
            if(t==null || !node.getId().equals(t.getInNodeId()) || !"iptables".equals(t.getEngine()) || !ids[1].equals(f.getUserId().toString())) continue;
            if(!ids[2].equals("0")) {
                UserTunnel permission=userTunnels.selectById(ids[2]);
                if(permission==null || !permission.getUserId().equals(f.getUserId()) || !permission.getTunnelId().equals(f.getTunnelId())) continue;
            } else if(!jdbc.queryForObject("SELECT role_id FROM user WHERE id=?",Integer.class,f.getUserId()).equals(0)) continue;
            long up=u.getLongValue("up"),down=u.getLongValue("down");if(up<0 || down<0) throw new IllegalArgumentException("negative usage");
            jdbc.update("INSERT IGNORE INTO engine_usage(node_id,epoch,service_id,sequence,up_bytes,down_bytes) VALUES(?,?,?,0,0,0)",node.getId(),epoch,name);
            Map<String,Object> old=jdbc.queryForMap("SELECT sequence,up_bytes,down_bytes FROM engine_usage WHERE node_id=? AND epoch=? AND service_id=? FOR UPDATE",node.getId(),epoch,name);
            long oldSeq=((Number)old.get("sequence")).longValue(),oldUp=((Number)old.get("up_bytes")).longValue(),oldDown=((Number)old.get("down_bytes")).longValue();
            if(seq<=oldSeq) continue;
            if(up<oldUp || down<oldDown) throw new IllegalArgumentException("cumulative counters regressed");
            jdbc.update("UPDATE engine_usage SET sequence=?,up_bytes=?,down_bytes=? WHERE node_id=? AND epoch=? AND service_id=?",seq,up,down,node.getId(),epoch,name);
            FlowDto delta=new FlowDto();delta.setN(name);delta.setD(up-oldUp);delta.setU(down-oldDown);flow.accountEngineDelta(delta);
        }
    }
}
