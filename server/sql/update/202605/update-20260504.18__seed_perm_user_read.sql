-- 系统权限：user:read
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1USERREAD', 26, '0'), 'user:read', '查看用户', 'user', 'read',
       '允许查看用户列表、详情、状态、登录记录等所有"用户读取"操作', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'user:read');
