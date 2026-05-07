-- 种子：系统角色 platform_admin（oneauth 平台超级管理员）
INSERT INTO roles (public_id, code, name, description, is_system)
SELECT LPAD('1PLATFORMADMIN', 26, '0'), 'platform_admin', 'Platform Admin',
       'oneauth 平台超级管理员', TRUE
WHERE NOT EXISTS (SELECT 1 FROM roles WHERE code = 'platform_admin');
