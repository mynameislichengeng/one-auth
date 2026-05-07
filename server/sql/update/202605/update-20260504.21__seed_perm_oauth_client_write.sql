-- 系统权限：oauth_client:write
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1OACLIENTWRITE', 26, '0'), 'oauth_client:write', '管理 Client', 'oauth_client', 'write',
       '允许新建/修改 OAuth Client、轮换 secret、配置 allowed_tenant_types', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'oauth_client:write');
