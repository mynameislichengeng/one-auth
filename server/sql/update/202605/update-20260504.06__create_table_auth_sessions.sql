-- oneauth 自身 SSO cookie session（详见 02 文档 §IV.1）
CREATE TABLE IF NOT EXISTS auth_sessions (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    session_id   CHAR(64)        NOT NULL,
    user_id      BIGINT UNSIGNED NOT NULL,
    ip           VARCHAR(45)     NULL,
    user_agent   TEXT            NULL,
    created_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen_at DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at   DATETIME(3)     NOT NULL,
    revoked_at   DATETIME(3)     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_session_id (session_id),
    KEY idx_user    (user_id, revoked_at),
    KEY idx_expires (expires_at),
    CONSTRAINT fk_auth_session_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='oneauth 自身 SSO cookie session';
