-- 系统权限：tenant:read
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1TENANTREAD', 26, '0'), 'tenant:read', '查看租户', 'tenant', 'read',
       '允许查看租户列表、配置', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'tenant:read');
