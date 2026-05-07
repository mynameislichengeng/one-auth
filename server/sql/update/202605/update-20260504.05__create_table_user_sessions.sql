-- Refresh token / 设备会话：rotation + 重放检测
CREATE TABLE IF NOT EXISTS user_sessions (
    id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id             BIGINT UNSIGNED NOT NULL,
    tenant_id           BIGINT UNSIGNED NOT NULL,
    client_id           VARCHAR(64)     NOT NULL,
    refresh_token_hash  CHAR(64)        NOT NULL,
    family_id           CHAR(26)        NOT NULL,
    parent_id           BIGINT UNSIGNED NULL,
    device_type         VARCHAR(32)     NULL,
    device_id           VARCHAR(128)    NULL,
    user_agent          TEXT            NULL,
    ip                  VARCHAR(45)     NULL,
    issued_at           DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    rotated_at          DATETIME(3)     NULL,
    revoked_at          DATETIME(3)     NULL,
    expires_at          DATETIME(3)     NOT NULL,
    last_used_at        DATETIME(3)     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_refresh_hash (refresh_token_hash),
    KEY idx_user_active (user_id, revoked_at, expires_at),
    KEY idx_family     (family_id),
    KEY idx_expires    (expires_at),
    CONSTRAINT fk_session_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Refresh token / 设备会话：rotation + 重放检测';
