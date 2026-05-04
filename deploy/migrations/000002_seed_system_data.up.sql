-- 系统级种子数据。幂等可重入。
-- 用 LPAD 保证 public_id 精确 26 字符（CHAR(26) 限制）。
-- 应用层 bootstrap 还会再确认一次。

-- 默认 main 租户
INSERT INTO tenants (public_id, code, name, type, status)
SELECT LPAD('1MAIN', 26, '0'), 'main', 'Platform', 'platform', 'active'
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE code = 'main');

-- 系统角色：platform_admin
INSERT INTO roles (public_id, code, name, description, is_system)
SELECT LPAD('1PLATFORMADMIN', 26, '0'), 'platform_admin', 'Platform Admin',
       'oneauth 平台超级管理员', TRUE
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE code = 'platform_admin');

-- 系统权限（oneauth admin 自身需要的）
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1USERREAD', 26, '0'), 'user:read', '查看用户', 'user', 'read',
       '允许查看用户列表、详情、状态、登录记录等所有"用户读取"操作', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'user:read');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1USERWRITE', 26, '0'), 'user:write', '编辑用户', 'user', 'write',
       '允许修改用户昵称、状态（冻结/解冻/封禁）；不含删除', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'user:write');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1OACLIENTREAD', 26, '0'), 'oauth_client:read', '查看 Client', 'oauth_client', 'read',
       '允许查看 OAuth Client 列表、配置、调用日志', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'oauth_client:read');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1OACLIENTWRITE', 26, '0'), 'oauth_client:write', '管理 Client', 'oauth_client', 'write',
       '允许新建/修改 OAuth Client、轮换 secret、配置 allowed_tenant_types', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'oauth_client:write');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1ROLEREAD', 26, '0'), 'role:read', '查看角色', 'role', 'read',
       '允许查看角色定义、权限分配、绑定用户列表', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'role:read');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1ROLEWRITE', 26, '0'), 'role:write', '管理角色', 'role', 'write',
       '允许新建/修改角色、绑定权限、给用户授予/撤销角色', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'role:write');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1TENANTREAD', 26, '0'), 'tenant:read', '查看租户', 'tenant', 'read',
       '允许查看租户列表、配置', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'tenant:read');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1TENANTWRITE', 26, '0'), 'tenant:write', '管理租户', 'tenant', 'write',
       '允许新建/修改租户、配置 type 字典；仅 platform_admin', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'tenant:write');

INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1AUDITREAD', 26, '0'), 'audit:read', '查看审计', 'audit', 'read',
       '允许查看登录日志、变更审核记录等审计数据', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'audit:read');

-- 把所有系统权限授予 platform_admin 角色
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.code = 'platform_admin' AND p.is_system = TRUE;
