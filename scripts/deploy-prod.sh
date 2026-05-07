#!/usr/bin/env bash
# 生产蓝绿部署入口（薄壳，转发到 ci-deploy.sh prod）
# 使用前确保已准备好 .env.prod 与生产 mysql / redis 可达
exec "$(dirname "$0")/ci-deploy.sh" prod "$@"
