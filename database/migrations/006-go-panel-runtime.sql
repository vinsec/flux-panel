-- Explicit, additive Go panel runtime migration. Existing Java ignores these tables.
-- Never applied automatically; no existing ledger or quota rows are changed.
CREATE TABLE IF NOT EXISTS panel_job_run (
 job_name VARCHAR(64) NOT NULL, period_key VARCHAR(64) NOT NULL,
 completed_at BIGINT NOT NULL, PRIMARY KEY(job_name,period_key)
) ENGINE=InnoDB;
CREATE TABLE IF NOT EXISTS panel_pending_batch (
 node_id BIGINT NOT NULL PRIMARY KEY, batch_id VARCHAR(64) NOT NULL,
 body LONGTEXT NOT NULL, created_at BIGINT NOT NULL
) ENGINE=InnoDB;
