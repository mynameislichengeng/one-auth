-- 把所有系统权限授予 platform_admin 角色（一次 CROSS JOIN 完成）
INSERT IGNORE INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r CROSS JOIN permissions p
WHERE r.code = 'platform_admin' AND p.is_system = TRUE;
