-- 用户-角色：按 tenant 维度授予
CREATE TABLE IF NOT EXISTS user_roles (
    id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id    BIGINT UNSIGNED NOT NULL,
    tenant_id  BIGINT UNSIGNED NOT NULL,
    role_id    BIGINT UNSIGNED NOT NULL,
    scope_type VARCHAR(64)     NOT NULL DEFAULT '',
    scope_id   VARCHAR(128)    NOT NULL DEFAULT '',
    granted_by BIGINT UNSIGNED NULL,
    granted_at DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at DATETIME(3)     NULL,
    revoked_at DATETIME(3)     NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_tenant_role_scope (user_id, tenant_id, role_id, scope_type, scope_id),
    KEY idx_tenant_role (tenant_id, role_id),
    KEY idx_user       (user_id),
    KEY idx_expires    (expires_at),
    CONSTRAINT fk_ur_user   FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    CONSTRAINT fk_ur_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fk_ur_role   FOREIGN KEY (role_id)   REFERENCES roles(id)   ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='用户-角色：按 tenant 维度授予';
