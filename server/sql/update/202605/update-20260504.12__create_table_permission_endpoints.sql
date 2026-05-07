-- Permission 关联接口列表（业务方启动/部署时上报，D-D10）
CREATE TABLE IF NOT EXISTS permission_endpoints (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    permission_id     BIGINT UNSIGNED NOT NULL,
    client_id         VARCHAR(64)     NOT NULL,
    method            VARCHAR(10)     NOT NULL,
    path_pattern      VARCHAR(255)    NOT NULL,
    description       VARCHAR(500)    NULL,
    deprecated        BOOLEAN         NOT NULL DEFAULT FALSE,
    last_sync_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_sync_version VARCHAR(64)     NULL,
    created_at        DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at        DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_client_method_path (client_id, method, path_pattern),
    KEY idx_permission (permission_id),
    KEY idx_client     (client_id),
    CONSTRAINT fk_pe_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='Permission 关联接口列表';
