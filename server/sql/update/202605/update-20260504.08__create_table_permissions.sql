-- 权限定义
CREATE TABLE IF NOT EXISTS permissions (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id   CHAR(26)        NOT NULL,
    code        VARCHAR(100)    NOT NULL,
    name        VARCHAR(200)    NOT NULL,
    resource    VARCHAR(64)     NOT NULL,
    action      VARCHAR(64)     NOT NULL,
    description VARCHAR(500)    NOT NULL,
    is_system   BOOLEAN         NOT NULL DEFAULT FALSE,
    client_id   VARCHAR(64)     NULL,
    created_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by  BIGINT UNSIGNED NULL,
    updated_by  BIGINT UNSIGNED NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_public_id (public_id),
    UNIQUE KEY uk_code (code),
    KEY idx_resource  (resource),
    KEY idx_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='权限定义';
