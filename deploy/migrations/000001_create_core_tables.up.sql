-- oneauth Stage 1 schema (15 张表)
-- 详细字段说明见 lc_todo/03-data-model.md
-- 字符集：utf8mb4 / utf8mb4_unicode_ci

-- ============================================================
-- 1. 身份层
-- ============================================================

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

CREATE TABLE IF NOT EXISTS user_tenant_memberships (
    id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id   BIGINT UNSIGNED NOT NULL,
    tenant_id BIGINT UNSIGNED NOT NULL,
    status    VARCHAR(20)     NOT NULL DEFAULT 'active',
    created_at DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3)    NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_tenant (user_id, tenant_id),
    KEY idx_tenant_status (tenant_id, status),
    KEY idx_user_status   (user_id, status),
    CONSTRAINT fk_membership_user   FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    CONSTRAINT fk_membership_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='用户-租户绑定关系';

-- ============================================================
-- 2. 会话层
-- ============================================================

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

-- ============================================================
-- 3. 权限层
-- ============================================================

CREATE TABLE IF NOT EXISTS roles (
    id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id   CHAR(26)        NOT NULL,
    code        VARCHAR(64)     NOT NULL,
    name        VARCHAR(200)    NOT NULL,
    description VARCHAR(500)    NULL,
    is_system   BOOLEAN         NOT NULL DEFAULT FALSE,
    created_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by  BIGINT UNSIGNED NULL,
    updated_by  BIGINT UNSIGNED NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_public_id (public_id),
    UNIQUE KEY uk_code (code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='角色定义（硬删，FK RESTRICT 防误删）';

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

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       BIGINT UNSIGNED NOT NULL,
    permission_id BIGINT UNSIGNED NOT NULL,
    granted_at    DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (role_id, permission_id),
    KEY idx_permission (permission_id),
    CONSTRAINT fk_rp_role       FOREIGN KEY (role_id)       REFERENCES roles(id)       ON DELETE CASCADE,
    CONSTRAINT fk_rp_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='角色-权限映射';

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

-- ============================================================
-- 4. 接入层
-- ============================================================

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id                   CHAR(26)        NOT NULL,
    client_id                   VARCHAR(64)     NOT NULL,
    client_secret_hash          VARCHAR(255)    NOT NULL,
    name                        VARCHAR(200)    NOT NULL,
    description                 VARCHAR(500)    NULL,
    client_type                 VARCHAR(32)     NOT NULL,
    redirect_uris               JSON            NOT NULL,
    grant_types                 JSON            NOT NULL,
    allowed_scopes              JSON            NOT NULL,
    allowed_tenant_types        JSON            NOT NULL,
    require_pkce                BOOLEAN         NOT NULL DEFAULT TRUE,
    access_token_ttl_seconds    INT UNSIGNED    NOT NULL DEFAULT 7200,
    refresh_token_ttl_seconds   INT UNSIGNED    NOT NULL DEFAULT 2592000,
    allowed_ip_cidrs            JSON            NULL,
    status                      VARCHAR(20)     NOT NULL DEFAULT 'active',
    created_at                  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at                  DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
    created_by                  BIGINT UNSIGNED NULL,
    updated_by                  BIGINT UNSIGNED NULL,
    deleted                     BOOLEAN         NOT NULL DEFAULT FALSE,
    PRIMARY KEY (id),
    UNIQUE KEY uk_public_id (public_id),
    UNIQUE KEY uk_client_id (client_id),
    KEY idx_status  (status, deleted),
    KEY idx_type    (client_type),
    KEY idx_deleted (deleted)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='OAuth Client（接入方应用）';

-- ============================================================
-- 4.5 接入治理层
-- ============================================================

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
  COMMENT='Permission 关联接口列表（业务方启动/部署时上报）';

CREATE TABLE IF NOT EXISTS permission_change_requests (
    id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    public_id         CHAR(26)        NOT NULL,
    client_id         VARCHAR(64)     NOT NULL,
    submitted_version VARCHAR(64)     NULL,
    payload           JSON            NOT NULL,
    diff_summary      JSON            NOT NULL,
    diff_hash         CHAR(64)        NOT NULL,
    status            VARCHAR(20)     NOT NULL DEFAULT 'pending',
    submitted_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    last_seen_at      DATETIME(3)     NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    seen_count        INT UNSIGNED    NOT NULL DEFAULT 1,
    reviewed_by       BIGINT UNSIGNED NULL,
    reviewed_at       DATETIME(3)     NULL,
    review_comment    VARCHAR(1000)   NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_public_id (public_id),
    KEY idx_client_status_diff (client_id, status, diff_hash),
    KEY idx_status_time        (status, submitted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  COMMENT='权限变更审核（diff-driven）';

-- ============================================================
-- 5. 安全层
-- ============================================================

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
