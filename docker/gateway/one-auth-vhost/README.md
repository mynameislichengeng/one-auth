# one-auth-vhost —— oneauth 在宿主机 nginx 上的 vhost 模板

## 是什么

**vhost** = **virtual host** = nginx 的 `server { ... }` 块。
本目录放的是 oneauth 项目要塞到**宿主机 nginx**（systemd 管理的 `nginx.service`，不在 docker 里）`/etc/nginx/conf.d/` 里的 server block 模板。

跟一台服务器上**所有项目共用同一个宿主机 nginx**——它对外暴露 443/80 端口、处理 HTTPS、按域名分发流量到各个项目。

## 整个 `docker/gateway/` 是网关配置总目录

```
docker/gateway/
├── one-auth-vhost/    ← 本目录（外层：宿主机 nginx vhost 模板，对外 HTTPS 入口）
│   ├── README.md
│   └── conf.d/
│       └── *.conf.example   各域名对应的 server block 模板
└── bg-proxy/          ← 内层（docker-compose 容器内 nginx，做蓝绿切换）
    ├── conf/
    │   └── default.conf
    └── slot.conf.example
```

## 跟 `bg-proxy/` 的区别

oneauth 部署完后**有两层 nginx**，职责不同：

```
互联网用户
  │  HTTPS https://auth.licheng.cn
  ▼
┌─────────────────────────────────────┐
│ 宿主机 nginx                         │  ← 用本目录 vhost 模板部署
│   - SSL 终结（证书在这里）          │
│   - 多项目按域名分发                 │
│       auth.licheng.cn  → oneauth    │
│       shop.licheng.cn  → shop 项目  │
│       blog.licheng.cn  → blog 项目  │
│   - 速率限制 / DDoS 第一道防线       │
└─────────────────┬───────────────────┘
                  │  HTTP proxy_pass http://127.0.0.1:${GATEWAY_HOST_PORT}
                  ▼
┌─────────────────────────────────────┐
│ bg-proxy（docker-compose 内 nginx） │  ← docker/gateway/bg-proxy/ 管这层
│   - 蓝绿切换（slot.conf 切 upstream）│
│   - 项目内 location 路由              │
│       /oauth/  /.well-known/  /api/  │
│   - 项目级 access log                │
└─────────────────┬───────────────────┘
                  │  HTTP proxy_pass http://oneauth-blue/green:8080
                  ▼
              Go 后端
```

| 层 | 物理位置 | 职责 | 跨项目共享？ |
|---|---|---|---|
| **宿主机 nginx**（用本目录模板）| 宿主机 systemd `nginx.service` | SSL 终结、域名分发、速率限制 | ✅ 一台服务器一份 nginx，多项目并存 |
| **bg-proxy**（`../bg-proxy/`）| docker-compose 容器 | 蓝绿切换、项目内 location 路由 | ❌ 每个项目自己一份 |

## 为什么不让 bg-proxy 直接对外（端口 443）

- **多项目共存**：一台服务器上不止 oneauth 一个项目，443 端口只有一个，必须由宿主机 nginx 统一持有再分发
- **SSL 证书**：证书放宿主机统一管理（certbot 自动续期），不需要每个项目容器都装
- **跨项目速率限制 / 黑名单**：在宿主机 nginx 一处配置，全站生效
- **解耦升级**：oneauth 蓝绿切换/重启时，宿主机 nginx 不动，其他项目流量不受影响

## 注意：本目录不进 docker-compose

本目录的内容**不会**被 oneauth 的 docker-compose 加载——它**不属于** docker-compose 栈。
它是**人工部署到宿主机** `/etc/nginx/conf.d/` 的模板参考。

`bg-proxy/` 才是 docker-compose 真正挂载的目录（`./docker/gateway/bg-proxy/conf/:/etc/nginx/conf.d/:ro`）。

## 部署步骤（以 prod 为例）

第一次在新服务器装 oneauth 时：

```bash
# 1. 装 nginx（一次性）
sudo apt install nginx                              # Debian/Ubuntu
# 或 sudo yum install nginx                         # CentOS/RHEL

# 2. 装 certbot 拿 SSL 证书（一次性）
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d auth.licheng.cn

# 3. 把项目 vhost 模板拷到 nginx 配置目录
sudo cp /opt/oneauth/docker/gateway/one-auth-vhost/conf.d/oneauth.conf.example \
        /etc/nginx/conf.d/oneauth.conf

# 4. 编辑替换占位符（域名、SSL 路径、upstream 端口）
sudo vim /etc/nginx/conf.d/oneauth.conf

# 5. reload
sudo nginx -t && sudo systemctl reload nginx
```

之后部署 oneauth 容器（蓝绿切换）**不需要再动宿主机 nginx**——bg-proxy 在 :80 反代上层来的流量即可。

## 跟 oneauth 自身蓝绿的关系

| 操作 | 宿主机 nginx 受影响吗？ |
|---|---|
| oneauth 蓝绿切槽 | ❌ 不受影响（bg-proxy 自己处理） |
| 加新 oneauth 配置（新 location） | ❌ 改 `../bg-proxy/conf/default.conf` 即可 |
| oneauth 重启 / 升级 | ❌ bg-proxy 容器永不重建 |
| **加新项目 / 加新域名** | ✅ 需要在宿主机 nginx 加新 vhost + reload |
| **SSL 证书续期** | ✅ certbot 自动改宿主机 nginx |
| **加全站速率限制** | ✅ 改宿主机 nginx |

→ 宿主机 nginx 是**慢变更**层，bg-proxy 是**快变更**层，两层解耦。

## prod 域名规划（参考 04-implementation-status / D-D10）

```
auth.licheng.cn          → oneauth（业务面：OAuth/OIDC 端点 + 登录页 + JWKS）
auth.admin.licheng.cn    → oneauth（管理面：admin SPA + admin BFF API，V0.3 接入）
```

模板见 `conf.d/oneauth.conf.example`。
