-- 权限变更审核（diff-driven，D-D10）
CREATE TABLE IF NOT EXISTS permission_change_requests (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id         CHAR(26)        NOT NULL,
    client_id         VARCHAR(64)     NOT NULL,
    submitted_version VARCHAR(64)     NULL,
    payload           JSON            NOT NULL,
    diff_summary      JSON            NOT NULL,
    diff_hash         CHAR(64)        NOT NULL,
    status            VARCHAR(20)     NOT NULL DEFAULT 'pending',
    submitted_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    seen_count        INT UNSIGNED    NOT NULL DEFAULT 1,
    reviewed_by       BIGINT UNSIGNED NULL,
    reviewed_at       DATETIME(3)     NULL,
    review_comment    VARCHAR(1000)   NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_public_id (public_id),
    KEY idx_client_status_diff (client_id, status, diff_hash),
    KEY idx_status_time        (status, submitted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='权限变更审核（diff-driven）';
