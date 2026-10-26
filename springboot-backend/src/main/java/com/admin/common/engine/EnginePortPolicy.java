package com.admin.common.engine;

import com.admin.entity.*;
import com.admin.mapper.NodeMapper;
import com.alibaba.fastjson.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import javax.sql.DataSource;
import java.sql.*;
import java.util.*;
import java.util.function.Supplier;

/** Cross-process physical-host arbitration; endpoint collisions remain typed. */
@Service
public class EnginePortPolicy {
    @Resource private JdbcTemplate jdbc;
    @Resource private DataSource dataSource;
    @Resource private NodeMapper nodes;
    private final java.util.concurrent.ConcurrentHashMap<String,java.util.concurrent.locks.ReentrantLock> locks=new java.util.concurrent.ConcurrentHashMap<>();
    public <T>T locked(Tunnel tunnel,Supplier<T> action){
        if(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive())
            throw new IllegalStateException("port mutations require their own autocommit boundary");
        Node node=nodes.selectById(tunnel.getInNodeId());if(node==null)return action.get();
        String host=node.getServerIp();if(host==null||host.isBlank())host="node:"+node.getId();
        String key="flux-port-"+NodeCredentials.hash(host.toLowerCase(Locale.ROOT)).substring(0,40);
        var mutex=locks.computeIfAbsent(key,k->new java.util.concurrent.locks.ReentrantLock());mutex.lock();
        Connection connection=null;boolean boundHere=false,acquired=false;
        try {
            connection=org.springframework.jdbc.datasource.DataSourceUtils.getConnection(dataSource);
            if(!org.springframework.transaction.support.TransactionSynchronizationManager.hasResource(dataSource)){
                // Reuse the lock's connection for MyBatis/JDBC on this thread.
                // No outer DB transaction is opened: writes stay visible before
                // synchronous credit requests, while unrelated hosts cannot
                // exhaust the pool by each waiting for a second connection.
                org.springframework.transaction.support.TransactionSynchronizationManager.bindResource(dataSource,new org.springframework.jdbc.datasource.ConnectionHolder(connection));
                boundHere=true;
            }
            try(PreparedStatement take=connection.prepareStatement("SELECT GET_LOCK(?,10)")){
                take.setString(1,key);try(ResultSet result=take.executeQuery()){if(!result.next()||result.getInt(1)!=1)throw new IllegalStateException("physical node port lock busy");}
            }
            acquired=true;return action.get();
        } catch(SQLException e){throw new IllegalStateException("physical node port arbitration unavailable");}
        finally {
            try {
                if(acquired)try(PreparedStatement release=connection.prepareStatement("SELECT RELEASE_LOCK(?)")){release.setString(1,key);release.executeQuery().close();}
            } catch(SQLException ignored) { /* closing the owned connection also releases its lock */ }
            finally {
                if(boundHere)org.springframework.transaction.support.TransactionSynchronizationManager.unbindResource(dataSource);
                if(connection!=null)org.springframework.jdbc.datasource.DataSourceUtils.releaseConnection(connection,dataSource);
                mutex.unlock();
            }
        }
    }
    public boolean typed(String options){return options!=null&&!options.isBlank()&&JSONObject.parseObject(options).containsKey("listeners");}
    private static JSONObject options(String value){return value==null||value.isBlank()?new JSONObject():JSONObject.parseObject(value);}
    private static ForwardSpec descriptor(Tunnel tunnel,Forward forward){ForwardSpec spec=new ForwardSpec("0_1_0",forward.getInPort(),null,forward.getRemoteAddr(),tunnel.getType(),tunnel,"fifo",null);spec.setEngineOptions(forward.getEngineOptions());return spec;}
    public void validate(Tunnel tunnel,Forward forward,Long exclude){
        Node node=nodes.selectById(tunnel.getInNodeId());if(node==null)throw new IllegalArgumentException("node missing");
        JSONArray desired=EngineSpecFactory.listeners(descriptor(tunnel,forward),options(forward.getEngineOptions()));boolean main=false;
        for(Object item:desired){JSONObject l=(JSONObject)item;int port=l.getIntValue("port");if(port<node.getPortSta()||port>node.getPortEnd())throw new IllegalArgumentException("listener port outside node allocation range");if(port==forward.getInPort())main=true;}
        if(!main)throw new IllegalArgumentException("at least one listener must use the allocated entry port");
        List<Map<String,Object>> peers=jdbc.queryForList("SELECT id FROM node WHERE id=? OR (server_ip=? AND server_ip<>'')",node.getId(),node.getServerIp());Set<Long> ids=new HashSet<>();for(var row:peers)ids.add(((Number)row.get("id")).longValue());String placeholders=String.join(",",Collections.nCopies(ids.size(),"?"));List<Object> args=new ArrayList<>(ids);args.addAll(ids);
        for(var row:jdbc.queryForList("SELECT f.id,f.in_port,f.out_port,f.remote_addr,f.engine_options,t.in_node_id,t.out_node_id,t.type,t.engine,t.tcp_listen_addr,t.udp_listen_addr FROM forward f JOIN tunnel t ON t.id=f.tunnel_id WHERE t.in_node_id IN ("+placeholders+") OR t.out_node_id IN ("+placeholders+")",args.toArray())){
            long id=((Number)row.get("id")).longValue();if(exclude!=null&&exclude==id)continue;
            JSONArray existing=new JSONArray();if(ids.contains(((Number)row.get("in_node_id")).longValue())){Tunnel t=new Tunnel();t.setTcpListenAddr(String.valueOf(row.get("tcp_listen_addr")));t.setUdpListenAddr(String.valueOf(row.get("udp_listen_addr")));t.setType(((Number)row.get("type")).intValue());Forward f=new Forward();f.setInPort(((Number)row.get("in_port")).intValue());f.setRemoteAddr(String.valueOf(row.get("remote_addr")));f.setEngineOptions((String)row.get("engine_options"));existing=EngineSpecFactory.listeners(descriptor(t,f),options(f.getEngineOptions()));}
            for(Object a:desired)for(Object b:existing){JSONObject l=(JSONObject)a,r=(JSONObject)b;if(l.getIntValue("port")!=r.getIntValue("port")||!l.getString("protocol").equals(r.getString("protocol")))continue;boolean family=l.getString("family").equals(r.getString("family"));String lh=l.getString("host"),rh=r.getString("host");boolean legacy="gost".equals(row.get("engine"))&&(rh.equals("::")||rh.equals("0.0.0.0"))||"gost".equals(node.getEngine())&&(lh.equals("::")||lh.equals("0.0.0.0"));if((family||legacy)&&(lh.equals(rh)||Set.of("::","0.0.0.0").contains(lh)||Set.of("::","0.0.0.0").contains(rh)))throw new IllegalArgumentException("listener conflicts with a reserved forwarding endpoint");}
            if(row.get("out_port")!=null&&row.get("out_node_id")!=null&&ids.contains(((Number)row.get("out_node_id")).longValue()))for(Object item:desired)if(((JSONObject)item).getIntValue("port")==((Number)row.get("out_port")).intValue())throw new IllegalArgumentException("listener conflicts with relay egress reservation");
        }
    }
}
