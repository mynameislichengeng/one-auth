-- 反向种子（仅清理 system 数据；不删用户产生的数据）

DELETE FROM role_permissions
 WHERE role_id IN (SELECT id FROM roles WHERE code = 'platform_admin' AND is_system = TRUE)
   AND permission_id IN (SELECT id FROM permissions WHERE is_system = TRUE);

DELETE FROM permissions WHERE is_system = TRUE;
DELETE FROM roles       WHERE is_system = TRUE;
DELETE FROM tenants     WHERE code = 'main';
