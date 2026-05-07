-- 系统权限：role:read
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1ROLEREAD', 26, '0'), 'role:read', '查看角色', 'role', 'read',
       '允许查看角色定义、权限分配、绑定用户列表', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'role:read');
