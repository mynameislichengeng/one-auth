-- 系统权限：audit:read
INSERT INTO permissions (public_id, code, name, resource, action, description, is_system)
SELECT LPAD('1AUDITREAD', 26, '0'), 'audit:read', '查看审计', 'audit', 'read',
       '允许查看登录日志、变更审核记录等审计数据', TRUE
WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE code = 'audit:read');
