-- Apply explicitly to a test DB first. This migration does not run on startup.
SET @q = IF(EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='node' AND column_name='engine'),'SELECT 1',"ALTER TABLE node ADD COLUMN engine VARCHAR(16) NOT NULL DEFAULT 'gost'");
PREPARE stmt FROM @q; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @q = IF(EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='tunnel' AND column_name='engine'),'SELECT 1',"ALTER TABLE tunnel ADD COLUMN engine VARCHAR(16) NOT NULL DEFAULT 'gost'");
PREPARE stmt FROM @q; EXECUTE stmt; DEALLOCATE PREPARE stmt;
CREATE TABLE IF NOT EXISTS engine_revision (
 node_id BIGINT NOT NULL, service_id VARCHAR(100) NOT NULL, revision BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(node_id,service_id)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS engine_usage (
 node_id BIGINT NOT NULL, epoch CHAR(32) NOT NULL, service_id VARCHAR(100) NOT NULL,
 sequence BIGINT NOT NULL DEFAULT 0, up_bytes BIGINT NOT NULL DEFAULT 0, down_bytes BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(node_id,epoch,service_id)
) ENGINE=InnoDB;
