-- 种子：默认 main 租户（platform 类型）
-- public_id 用 LPAD 占位（CHAR(26) 限制），应用层 bootstrap 不依赖具体值
INSERT INTO tenants (public_id, code, name, type, status)
SELECT LPAD('1MAIN', 26, '0'), 'main', 'Platform', 'platform', 'active'
WHERE NOT EXISTS (SELECT 1 FROM tenants WHERE code = 'main');
