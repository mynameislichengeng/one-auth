-- JWT access_token 黑名单（用户登出/强制下线时加进来）
-- D-F1：必须走 MySQL，不能走 cache（重启后丢失会让已撤销 token 复活）
CREATE TABLE IF NOT EXISTS jwt_blocklist (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    jti        CHAR(26)        NOT NULL,
    user_id    BIGINT UNSIGNED NOT NULL,
    reason     VARCHAR(64)     NOT NULL,
    revoked_at DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at DATETIME(3)     NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_jti (jti),
    KEY idx_user    (user_id),
    KEY idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='JWT access_token 黑名单';
