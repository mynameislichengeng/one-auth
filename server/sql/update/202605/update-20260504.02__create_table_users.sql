-- 用户身份：与 tenant 解耦（D-B5 成员关系型）
CREATE TABLE IF NOT EXISTS users (
    id            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id     CHAR(26)        NOT NULL,
    nickname      VARCHAR(100)    NOT NULL,
    avatar_url    VARCHAR(500)    NULL,
    status        VARCHAR(20)     NOT NULL DEFAULT 'active',
    status_reason VARCHAR(500)    NULL,
    metadata      JSON            NULL,
    created_at    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by    BIGINT UNSIGNED NULL,
    updated_by    BIGINT UNSIGNED NULL,
    deleted       BOOLEAN         NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uk_public_id (public_id),
    KEY idx_status  (status, deleted),
    KEY idx_deleted (deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='用户身份：与 tenant 解耦';
