-- 系统权限：role:write
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1ROLEWRITE', 26, '0'), 'role:write', '管理角色', 'role', 'write',
       '允许新建/修改角色、绑定权限、给用户授予/撤销角色', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'role:write');
