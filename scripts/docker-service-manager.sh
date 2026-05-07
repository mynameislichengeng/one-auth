#!/usr/bin/env bash
# scripts/docker-service-manager.sh — oneauth 容器栈日常运维入口
#
# 职责：只管"已经在跑的 docker service"——停、看、清、查 OAuth client。
# 启动 / 部署 / 切换蓝绿一律走 ./scripts/deploy-{local,prod}.sh，本脚本不做启动入口。
#
# 用法:
#   ./scripts/docker-service-manager.sh down            # 停所有容器（mysql/redis/blue/green/gateway）
#   ./scripts/docker-service-manager.sh clean           # 停 + 清 docker/data/*（清完手动跑 deploy-local.sh 重启）
#   ./scripts/docker-service-manager.sh status          # 看容器状态（含所有 profile）
#   ./scripts/docker-service-manager.sh logs [svc]      # 跟日志（默认当前活跃槽 oneauth-{blue|green}）
#   ./scripts/docker-service-manager.sh e2e             # 跑端到端测试（栈必须已起）
#   ./scripts/docker-service-manager.sh secrets         # 打印 dev bootstrap 出的 client_id / secret

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# 所有 profile 一次性传给 docker compose（停止 / 状态用）
ALL_PROFILES="--profile mysql --profile redis --profile blue --profile green"

ensure_docker() {
  if ! docker info >/dev/null 2>&1; then
    echo "==> 错误：docker 未运行" >&2
    exit 1
  fi
}

# 读 slot.conf 推断当前活跃槽（blue / green / none）
current_slot() {
  local data_dir="${DATA_DIR:-./docker/data}"
  local slot_conf="${data_dir}/nginx/slot.conf"
  if [ -f "${slot_conf}" ]; then
    grep -oE 'oneauth-(blue|green)' "${slot_conf}" 2>/dev/null | head -1 | sed 's/oneauth-//' || echo "none"
  else
    echo "none"
  fi
}

cmd_down() {
  ensure_docker
  # shellcheck disable=SC2086
  docker compose ${ALL_PROFILES} down
}

# 清空：停容器 + 清数据卷 + 清 docker/data/*
# 不做启动——清完后请手动跑 ./scripts/deploy-local.sh 重新部署
cmd_clean() {
  ensure_docker
  echo "==> 停所有容器并清卷"
  # shellcheck disable=SC2086
  docker compose ${ALL_PROFILES} down -v
  echo "==> 清 docker/data/*"
  rm -rf docker/data/mysql/* docker/data/redis/* docker/data/oneauth/* docker/data/nginx/slot.conf docker/data/nginx/slot.conf.bak
  # 保留 .gitkeep
  touch docker/data/mysql/.gitkeep docker/data/redis/.gitkeep docker/data/oneauth/.gitkeep docker/data/nginx/.gitkeep
  echo ""
  echo "==> 清空完成。重新部署请运行: ./scripts/deploy-local.sh"
}

cmd_logs() {
  ensure_docker
  local svc="${1:-}"
  if [ -z "${svc}" ]; then
    local slot
    slot=$(current_slot)
    if [ "${slot}" = "none" ]; then
      echo "==> 当前没有活跃槽位（slot.conf 缺失），用法: $0 logs [oneauth-blue|oneauth-green|gateway|mysql|redis]" >&2
      exit 1
    fi
    svc="oneauth-${slot}"
    echo "==> 跟随当前活跃槽日志: ${svc}"
  fi
  # shellcheck disable=SC2086
  docker compose ${ALL_PROFILES} logs -f "${svc}"
}

cmd_status() {
  ensure_docker
  # shellcheck disable=SC2086
  docker compose ${ALL_PROFILES} ps
  echo
  local slot
  slot=$(current_slot)
  echo "当前活跃槽位: ${slot}"
}

cmd_e2e() {
  ensure_docker
  if ! docker ps --format '{{.Names}}' | grep -qx "oneauth-gateway"; then
    echo "==> 错误：oneauth-gateway 未运行，先 ./scripts/deploy-local.sh" >&2
    exit 1
  fi
  # 蓝绿后所有流量走 gateway；e2e 用 BASE_URL 变量（test_e2e.sh 第 20 行约定）
  local port="${GATEWAY_HOST_PORT:-80}"
  echo "==> e2e BASE_URL=http://localhost:${port}"
  BASE_URL="http://localhost:${port}" bash server/scripts/test_e2e.sh
}

cmd_secrets() {
  ensure_docker
  echo "==> dev 期 bootstrap 出的 OAuth Client（仅首次创建该 client 的槽日志里有）"
  for slot in blue green; do
    local svc="oneauth-${slot}"
    if docker ps -a --format '{{.Names}}' | grep -qx "${svc}"; then
      echo "----- ${svc} -----"
      docker logs "${svc}" 2>&1 \
        | grep -E "client_id|client_secret|grant_types|redirect_uri|=====" \
        | head -40 || true
    fi
  done
  echo
  echo "若没看到 client_secret，说明 client 已存在（仅首次创建时打印一次）；用 reset 重来或在 admin UI 轮换。"
}

case "${1:-help}" in
  down)      cmd_down ;;
  clean)     cmd_clean ;;
  logs)      shift; cmd_logs "${1:-}" ;;
  status|ps) cmd_status ;;
  e2e)       cmd_e2e ;;
  secrets)   cmd_secrets ;;
  -h|--help|help)
    sed -n '2,14p' "${BASH_SOURCE[0]}"
    ;;
  up|reset|deploy|start)
    echo "==> 错误：'$1' 不在本脚本职责内（启动 / 部署）" >&2
    echo "    本脚本只管已经在跑的 docker service；启动请运行：./scripts/deploy-local.sh" >&2
    exit 2
    ;;
  *)
    echo "未知子命令: $1" >&2
    echo "支持: down | clean | logs [svc] | status | e2e | secrets" >&2
    echo "（启动请用 ./scripts/deploy-local.sh）" >&2
    exit 2
    ;;
esac
