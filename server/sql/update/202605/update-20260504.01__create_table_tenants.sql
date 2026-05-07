-- 租户：identity 容器与数据隔离边界
CREATE TABLE IF NOT EXISTS tenants (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id   CHAR(26)        NOT NULL,
    code        VARCHAR(64)     NOT NULL,
    name        VARCHAR(200)    NOT NULL,
    type        VARCHAR(32)     NOT NULL,
    status      VARCHAR(20)     NOT NULL DEFAULT 'active',
    settings    JSON            NULL,
    created_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by  BIGINT UNSIGNED NULL,
    updated_by  BIGINT UNSIGNED NULL,
    deleted     BOOLEAN         NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uk_public_id (public_id),
    UNIQUE KEY uk_code (code),
    KEY idx_type    (type),
    KEY idx_status  (status, deleted),
    KEY idx_deleted (deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='租户：identity 容器与数据隔离边界';
