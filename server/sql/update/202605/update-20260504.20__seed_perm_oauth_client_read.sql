-- 系统权限：oauth_client:read
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1OACLIENTREAD', 26, '0'), 'oauth_client:read', '查看 Client', 'oauth_client', 'read',
       '允许查看 OAuth Client 列表、配置、调用日志', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'oauth_client:read');
