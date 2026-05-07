-- 登录凭证：(auth_type, auth_source, identifier) 全局唯一
CREATE TABLE IF NOT EXISTS user_auth (
    id           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id      BIGINT UNSIGNED NOT NULL,
    auth_type    VARCHAR(32)     NOT NULL,
    auth_source  VARCHAR(64)     NOT NULL DEFAULT '',
    identifier   VARCHAR(255)    NOT NULL,
    credential   VARCHAR(255)    NULL,
    verified_at  DATETIME(3)     NULL,
    last_used_at DATETIME(3)     NULL,
    metadata     JSON            NULL,
    created_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at   DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_auth_identifier (auth_type, auth_source, identifier),
    KEY idx_user      (user_id),
    KEY idx_last_used (last_used_at),
    CONSTRAINT fk_user_auth_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='登录凭证：identifier 全局唯一';
