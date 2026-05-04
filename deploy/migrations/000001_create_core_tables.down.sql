-- 反向 DROP（注意 FK 依赖：先删引用方，再删被引用方）

DROP TABLE IF EXISTS login_attempts;
DROP TABLE IF EXISTS jwt_blocklist;
DROP TABLE IF EXISTS permission_change_requests;
DROP TABLE IF EXISTS permission_endpoints;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS auth_sessions;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS user_tenant_memberships;
DROP TABLE IF EXISTS user_auth;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;
