-- Explicit migration; repeatable on MySQL 5.7/8. No automatic production DDL.
CREATE TABLE IF NOT EXISTS engine_node_policy (
 node_id BIGINT NOT NULL PRIMARY KEY,
 strict_credit TINYINT NOT NULL DEFAULT 0,
 updated_at BIGINT NOT NULL DEFAULT 0
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS engine_credit_lease (
 lease_id CHAR(32) NOT NULL PRIMARY KEY,
 node_id BIGINT NOT NULL, epoch CHAR(32) NOT NULL, boot_id VARCHAR(100) NOT NULL,
 service_id VARCHAR(100) NOT NULL, user_id BIGINT NOT NULL, user_tunnel_id BIGINT NOT NULL,
 generation BIGINT NOT NULL DEFAULT 1, total_raw BIGINT NOT NULL DEFAULT 0,
 consumed_raw BIGINT NOT NULL DEFAULT 0, reserved_bill BIGINT NOT NULL DEFAULT 0,
 start_up BIGINT NOT NULL DEFAULT 0, start_down BIGINT NOT NULL DEFAULT 0,
 ratio DECIMAL(16,6) NOT NULL, flow_type INT NOT NULL,
 closed TINYINT NOT NULL DEFAULT 0, lost TINYINT NOT NULL DEFAULT 0,
 expires_at BIGINT NOT NULL, updated_at BIGINT NOT NULL,
 INDEX credit_owner(user_id,closed), INDEX credit_permission(user_tunnel_id,closed),
 INDEX credit_node(node_id,epoch,boot_id,service_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS engine_credit_request (
 node_id BIGINT NOT NULL, epoch CHAR(32) NOT NULL, sequence BIGINT NOT NULL,
 body_hash CHAR(64) NOT NULL, response LONGTEXT NOT NULL, created_at BIGINT NOT NULL,
 PRIMARY KEY(node_id,epoch,sequence)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS engine_report_cursor (
 node_id BIGINT NOT NULL, epoch CHAR(32) NOT NULL, sequence BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(node_id,epoch)
) ENGINE=InnoDB;
