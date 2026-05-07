-- 登录尝试日志（成功 + 失败都记，用于防爆破和审计）
CREATE TABLE IF NOT EXISTS login_attempts (
    id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    auth_type      VARCHAR(32)     NOT NULL,
    identifier     VARCHAR(255)    NOT NULL,
    ip             VARCHAR(45)     NOT NULL,
    success        BOOLEAN         NOT NULL,
    failure_reason VARCHAR(64)     NULL,
    user_agent     TEXT            NULL,
    user_id        BIGINT UNSIGNED NULL,
    attempted_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    KEY idx_identifier_time (auth_type, identifier, attempted_at),
    KEY idx_ip_time         (ip, attempted_at),
    KEY idx_user_time       (user_id, attempted_at),
    KEY idx_attempted_at    (attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='登录尝试日志（防爆破 + 审计）';
