#!/usr/bin/env bash
# 本地蓝绿部署入口（薄壳，转发到 ci-deploy.sh local）
exec "$(dirname "$0")/ci-deploy.sh" local "$@"
