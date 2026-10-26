package com.admin.common.engine;

import com.admin.entity.Node;
import com.admin.entity.Tunnel;
import com.admin.mapper.NodeMapper;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import javax.sql.DataSource;
import java.sql.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class PortArbitrationTest {
    @Test
    void lockAndActionShareOnePoolConnectionWithoutAnOuterTransaction() throws Exception {
        DataSource source=mock(DataSource.class);Connection connection=mock(Connection.class);
        PreparedStatement take=mock(PreparedStatement.class),release=mock(PreparedStatement.class);
        ResultSet taken=mock(ResultSet.class),released=mock(ResultSet.class);
        when(source.getConnection()).thenReturn(connection);when(connection.getAutoCommit()).thenReturn(true);
        when(connection.prepareStatement("SELECT GET_LOCK(?,10)")).thenReturn(take);
        when(connection.prepareStatement("SELECT RELEASE_LOCK(?)")).thenReturn(release);
        when(take.executeQuery()).thenReturn(taken);when(taken.next()).thenReturn(true);when(taken.getInt(1)).thenReturn(1);when(release.executeQuery()).thenReturn(released);
        NodeMapper nodes=mock(NodeMapper.class);Node node=new Node();node.setId(1L);node.setServerIp("192.0.2.1");when(nodes.selectById(1L)).thenReturn(node);
        EnginePortPolicy policy=new EnginePortPolicy();ReflectionTestUtils.setField(policy,"dataSource",source);ReflectionTestUtils.setField(policy,"nodes",nodes);
        Tunnel tunnel=new Tunnel();tunnel.setInNodeId(1L);
        assertEquals("done",policy.locked(tunnel,()->{
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive());
            Connection used=DataSourceUtils.getConnection(source);assertSame(connection,used);DataSourceUtils.releaseConnection(used,source);
            new TransactionTemplate(new DataSourceTransactionManager(source)).execute(status->{
                assertTrue(TransactionSynchronizationManager.isActualTransactionActive());
                assertSame(connection,DataSourceUtils.getConnection(source));return null;
            });
            assertFalse(TransactionSynchronizationManager.isActualTransactionActive());return "done";
        }));
        assertFalse(TransactionSynchronizationManager.hasResource(source));
        verify(source,times(1)).getConnection();verify(connection,times(1)).close();
    }
}
