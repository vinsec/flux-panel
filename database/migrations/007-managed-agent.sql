-- Explicit, additive; does not change any existing engine, identity or ledger.
SET @q = IF(EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='node' AND column_name='forwarding_mode'),'SELECT 1',"ALTER TABLE node ADD COLUMN forwarding_mode VARCHAR(16) NOT NULL DEFAULT 'kernel'");
PREPARE stmt FROM @q; EXECUTE stmt; DEALLOCATE PREPARE stmt;
CREATE TABLE IF NOT EXISTS engine_mode_switch (
 node_id BIGINT NOT NULL PRIMARY KEY, operation_id VARCHAR(100) NOT NULL,
 from_mode VARCHAR(16) NOT NULL, to_mode VARCHAR(16) NOT NULL,
 status VARCHAR(20) NOT NULL, error_text VARCHAR(2048) NOT NULL DEFAULT '',
 updated_at BIGINT NOT NULL, UNIQUE KEY(operation_id)
) ENGINE=InnoDB;
