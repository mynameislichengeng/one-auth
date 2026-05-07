-- 系统权限：user:write
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1USERWRITE', 26, '0'), 'user:write', '编辑用户', 'user', 'write',
       '允许修改用户昵称、状态（冻结/解冻/封禁）；不含删除', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'user:write');
