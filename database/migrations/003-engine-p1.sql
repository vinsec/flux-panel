-- Explicit, repeatable MySQL 5.7/8 migration. Never applied automatically.
SET @q = IF(EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='forward' AND column_name='engine_options'),'SELECT 1','ALTER TABLE forward ADD COLUMN engine_options LONGTEXT NULL');
PREPARE stmt FROM @q; EXECUTE stmt; DEALLOCATE PREPARE stmt;
CREATE TABLE IF NOT EXISTS engine_session (
 token_hash CHAR(64) NOT NULL PRIMARY KEY, node_id BIGINT NOT NULL,
 created_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
 INDEX session_node(node_id,expires_at)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS engine_bandwidth_group (
 node_id BIGINT NOT NULL, scope VARCHAR(16) NOT NULL, owner_id BIGINT NOT NULL,
 up_bits BIGINT NOT NULL DEFAULT 0, down_bits BIGINT NOT NULL DEFAULT 0,
 updated_at BIGINT NOT NULL, PRIMARY KEY(node_id,scope,owner_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS engine_audit (
 id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY, created_at BIGINT NOT NULL,
 user_id BIGINT NULL, node_id BIGINT NULL, action VARCHAR(64) NOT NULL,
 service_id VARCHAR(100) NULL, detail VARCHAR(2048) NOT NULL,
 INDEX audit_node(node_id,created_at)
) ENGINE=InnoDB;
