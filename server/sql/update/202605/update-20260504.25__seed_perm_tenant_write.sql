-- 系统权限：tenant:write
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1TENANTWRITE', 26, '0'), 'tenant:write', '管理租户', 'tenant', 'write',
       '允许新建/修改租户、配置 type 字典；仅 platform_admin', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'tenant:write');
