#!/usr/bin/env bash
# oneauth 蓝绿发布主入口（local / prod 共用）
# 用法: bash scripts/ci-deploy.sh <local|prod>
#
# 参考：
#   - weixin/scripts/ci-deploy.sh
#   - /Users/licheng/lcClaw/work/devops/nginx/blue-green/02-实操指南.md
#
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# !!         【编码规范】修改此脚本必须遵守此规则                        !!
# !!  本脚本含中文字符。变量后紧跟中文字符（汉字 / 全角标点）时          !!
# !!  某些 bash 版本会把中文首字节当作变量名一部分，导致报错。           !!
# !!  规则：所有变量统一 ${VAR} 花括号形式，禁止裸写 $VAR。              !!
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
set -euo pipefail

# ==================== 参数 ====================
ENV="${1:-}"

if [ -z "${ENV}" ] || [[ ! "${ENV}" =~ ^(local|prod)$ ]]; then
    cat <<EOF

用法: bash scripts/ci-deploy.sh <local|prod>

  local - 本地开发环境（启动 mysql + redis 容器）
  prod  - 生产环境（mysql 用阿里云 RDS，redis 用云 Redis；不启基础设施）

EOF
    exit 1
fi

# 切到项目根（无论从哪调用）
cd "$(dirname "$0")/.."
echo "[init] 工作目录: $(pwd)"

# ==================== 环境差异收敛到 case ====================
# 约定：每个环境对应一份 .env.${ENV}（.env.local / .env.prod 等），
# 都不进 git；进 git 的只有 .env.example 模板。
# 详见 /Users/licheng/lcClaw/work/devops/docker/config-env-lc/README.md
case "${ENV}" in
    local)
        ENV_FILE=".env.local"
        DC="docker compose --env-file .env.local"
        INFRA_PROFILES="--profile mysql --profile redis"
        DRAIN_WAIT_DEFAULT=5
        ;;
    prod)
        ENV_FILE=".env.prod"
        DC="docker compose --env-file .env.prod"
        INFRA_PROFILES=""
        DRAIN_WAIT_DEFAULT=30
        ;;
esac

if [ ! -f "${ENV_FILE}" ]; then
    echo "[init] ❌ 未找到 ${ENV_FILE}"
    if [ "${ENV}" = "local" ]; then
        echo "       请先: cp .env.example .env.local 并填入密码"
    else
        echo "       请先准备 .env.prod（参考 .env.example）"
    fi
    exit 1
fi
echo "[init] 加载: ${ENV_FILE}"
set -a
# shellcheck disable=SC1090
source "${ENV_FILE}"
set +a

# 自检：.env.${ENV} 里 APP_ENV 必须跟脚本参数一致（防错配）
if [ "${APP_ENV:-}" != "${ENV}" ]; then
    echo "[init] ❌ ${ENV_FILE} 里 APP_ENV=${APP_ENV:-未设置}，但脚本参数是 ${ENV}"
    echo "       请确认 ${ENV_FILE} 里有 APP_ENV=${ENV}"
    exit 1
fi

# ==================== 派生变量（不入 env） ====================
DATA_DIR="${DATA_DIR:-./docker/data}"
SLOT_CONF="${DATA_DIR}/nginx/slot.conf"
SLOT_CONF_BAK="${SLOT_CONF}.bak"
GATEWAY_CONTAINER="oneauth-gateway"
DRAIN_WAIT="${DRAIN_WAIT:-${DRAIN_WAIT_DEFAULT}}"
MAX_WAIT=120

echo "[init] DATA_DIR=${DATA_DIR}"
echo "[init] SLOT_CONF=${SLOT_CONF}"

# ==================== Trap：失败回滚 slot.conf ====================
_SLOT_CONF_MODIFIED=false
cleanup() {
    EXIT_CODE=$?
    if [ "${_SLOT_CONF_MODIFIED}" = "true" ] && [ -f "${SLOT_CONF_BAK}" ]; then
        echo ""
        echo "[cleanup] 检测到异常 (exit=${EXIT_CODE})，回滚 slot.conf..."
        cp "${SLOT_CONF_BAK}" "${SLOT_CONF}"
        docker exec "${GATEWAY_CONTAINER}" nginx -s reload 2>/dev/null || true
        echo "[cleanup] slot.conf 已回滚 + nginx reload"
    fi
    rm -f "${SLOT_CONF_BAK}"
}
trap cleanup EXIT

# ==================== 防线 3：inode 校验 ====================
# 检测容器所有 bind mount 的宿主机 inode 与容器内 inode 是否一致
# 不一致说明 mount 已 dangling（rm -rf 仓库 / git checkout 重建目录等触发）
# 返回 0 = 一致；1 = 有不一致（建议 force-recreate）
check_mount_inode() {
    local container=$1
    local violations=()
    if ! docker ps --format '{{.Names}}' | grep -qx "${container}"; then
        echo "  ℹ ${container} 未运行，跳过 inode 校验"
        return 0
    fi
    while IFS='|' read -r src dst; do
        [ -z "${src}" ] && continue
        if [ ! -e "${src}" ]; then
            violations+=("${src} → ${dst} (宿主机源不存在)")
            continue
        fi
        local host_inode ctnr_inode
        # macOS BSD stat 用 -f；Linux GNU stat 用 -c。脚本兼容两边。
        host_inode=$(stat -f %i "${src}" 2>/dev/null || stat -c %i "${src}" 2>/dev/null || echo "missing")
        ctnr_inode=$(docker exec "${container}" stat -c %i "${dst}" 2>/dev/null || echo "missing")
        if [ "${host_inode}" != "${ctnr_inode}" ]; then
            violations+=("${src}(inode=${host_inode}) → ${dst}(inode=${ctnr_inode})")
        fi
    done < <(docker inspect "${container}" --format \
        '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}|{{.Destination}}{{println}}{{end}}{{end}}')

    if [ ${#violations[@]} -gt 0 ]; then
        echo "⚠️  ${container} bind mount inode 不一致："
        printf '   %s\n' "${violations[@]}"
        return 1
    fi
    return 0
}

ensure_mount_inode_consistent() {
    local container=$1
    if ! check_mount_inode "${container}"; then
        echo "  → 自动 force-recreate ${container} 修复 dangling mount..."
        ${DC} up -d --force-recreate "${container}"
        if ! check_mount_inode "${container}"; then
            echo "❌ force-recreate 后仍不一致，部署中止"
            exit 1
        fi
        echo "  ✓ ${container} 已重建，bind mount 已恢复"
    fi
}

# ==================== 流程展示 ====================
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║          oneauth 蓝绿部署                                    ║"
echo "╠════════════════════════════════════════════════════════════╣"
case "${ENV}" in
    local) echo "║  环境: local（启动 mysql + redis 容器）                      ║" ;;
    prod)  echo "║  环境: prod（用云 RDS + 云 Redis，不启基础设施容器）          ║" ;;
esac
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  [1/5] 检查槽位 → 自动选择目标（blue/green）                 ║"
echo "║  [2/5] 启动基础设施（local: mysql + redis）                   ║"
echo "║  [3/5] 构建 + 启动 oneauth 新槽（含自动迁移 + bootstrap）     ║"
echo "║  [4/5] 启 gateway + 切流量（slot.conf + nginx reload）        ║"
echo "║  [5/5] 排水 + 停旧槽                                          ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# ==================== Step 1: 检查槽位 ====================
echo "========== [步骤 1/5] 检查槽位 =========="

if [ -f "${SLOT_CONF}" ]; then
    echo "[step1] 读取 ${SLOT_CONF}"
    CURRENT=$(grep -oE 'oneauth-(blue|green)' "${SLOT_CONF}" 2>/dev/null | head -1 | sed 's/oneauth-//' || echo "none")
else
    echo "[step1] slot.conf 不存在（首次部署）"
    CURRENT="none"
fi
[[ "${CURRENT}" =~ ^(blue|green)$ ]] || CURRENT="none"
echo "[step1] 当前槽位: CURRENT=${CURRENT}"

if [ "${CURRENT}" = "none" ]; then
    NEXT="blue"
    DEPLOY_TYPE="first"
elif [ "${CURRENT}" = "blue" ]; then
    NEXT="green"
    DEPLOY_TYPE="switch"
else
    NEXT="blue"
    DEPLOY_TYPE="switch"
fi

if [ "${DEPLOY_TYPE}" = "first" ]; then
    echo "[step1] 部署类型: 首次部署，目标槽位: ${NEXT}"
else
    echo "[step1] 部署类型: 蓝绿切换 ${CURRENT} → ${NEXT}"
fi

# ==================== Step 2: 启基础设施 ====================
echo ""
echo "========== [步骤 2/5] 启动基础设施 =========="
if [ -n "${INFRA_PROFILES}" ]; then
    # shellcheck disable=SC2086
    ${DC} ${INFRA_PROFILES} up -d mysql redis

    echo "[step2] 等 mysql healthy..."
    WAITED=0
    until docker inspect --format='{{.State.Health.Status}}' oneauth-mysql 2>/dev/null | grep -q "healthy"; do
        sleep 2; WAITED=$((WAITED + 2))
        if [ "${WAITED}" -ge 60 ]; then
            echo "[step2] ❌ mysql 启动超时"; exit 1
        fi
    done
    echo "[step2] mysql 健康（耗时 ${WAITED}s）"

    echo "[step2] 等 redis healthy..."
    WAITED=0
    until docker inspect --format='{{.State.Health.Status}}' oneauth-redis 2>/dev/null | grep -q "healthy"; do
        sleep 2; WAITED=$((WAITED + 2))
        if [ "${WAITED}" -ge 30 ]; then
            echo "[step2] ❌ redis 启动超时"; exit 1
        fi
    done
    echo "[step2] redis 健康（耗时 ${WAITED}s）"
else
    echo "[step2] 跳过（prod 用云基础设施）"
fi

# ==================== Step 3: 构建 + 启动 oneauth 新槽 ====================
echo ""
echo "========== [步骤 3/5] 构建 + 启动 oneauth-${NEXT} =========="

${DC} --profile "${NEXT}" build "oneauth-${NEXT}"
echo "[step3] 镜像构建完成"

${DC} --profile "${NEXT}" up -d "oneauth-${NEXT}"
echo "[step3] oneauth-${NEXT} 已启动，等待健康检查..."

WAITED=0
until docker inspect --format='{{.State.Health.Status}}' "oneauth-${NEXT}" 2>/dev/null | grep -q "healthy"; do
    sleep 2; WAITED=$((WAITED + 2))
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' "oneauth-${NEXT}" 2>/dev/null || echo "unknown")
    echo "[step3] [${WAITED}s/${MAX_WAIT}s] 状态: ${STATUS}"
    if [ "${WAITED}" -ge "${MAX_WAIT}" ]; then
        echo "[step3] ❌ oneauth-${NEXT} 启动超时"
        ${DC} --profile "${NEXT}" stop "oneauth-${NEXT}"
        exit 1
    fi
done
echo "[step3] oneauth-${NEXT} 已就绪（耗时 ${WAITED}s）"

# ==================== Step 4: 启 gateway + 切流量 ====================
echo ""
echo "========== [步骤 4/5] 启 Gateway + 切流量 =========="
echo ""
if [ "${CURRENT}" = "none" ]; then
    echo "  即将切换: 首次部署 → ${NEXT}"
else
    echo "  即将切换: ${CURRENT}  →  ${NEXT}"
fi
echo ""

# 防线 2：自愈 slot.conf 残留目录（带 sanity check）
if [ -d "${SLOT_CONF}" ]; then
    case "${SLOT_CONF}" in
        "${DATA_DIR}"/nginx/*)
            echo "[step4] ⚠ ${SLOT_CONF} 是目录残留，清理后重建为文件"
            rm -rf "${SLOT_CONF}" ;;
        *)
            echo "[step4] ❌ 拒绝删除非预期路径: ${SLOT_CONF}"; exit 1 ;;
    esac
fi

mkdir -p "$(dirname "${SLOT_CONF}")"

# 备份原 slot.conf（trap 回滚用）
if [ -f "${SLOT_CONF}" ]; then
    echo "[step4] 备份原配置: ${SLOT_CONF} → ${SLOT_CONF_BAK}"
    cp "${SLOT_CONF}" "${SLOT_CONF_BAK}"
fi

# 防线 1：先生成 slot.conf 再启 gateway
# cat/sed 的 truncate-write 不换 inode，单文件 mount 保持有效
echo "[step4] 渲染 slot.conf: upstream=oneauth-${NEXT}:8080"
sed -e "s|{{API_SERVER}}|oneauth-${NEXT}|g" \
    -e '/^#/d' \
    docker/gateway/bg-proxy/slot.conf.example > "${SLOT_CONF}"
sync
echo "[step4] slot.conf 已写入"

# 此后异常会触发 trap 回滚
_SLOT_CONF_MODIFIED=true

# 防线 3：检测 gateway bind mount 是否健康，dangling 时 force-recreate
ensure_mount_inode_consistent "${GATEWAY_CONTAINER}"

echo "[step4] 启动 ${GATEWAY_CONTAINER}"
${DC} up -d gateway

# macOS Docker Desktop / OrbStack 的 bind mount 偶尔同步延迟
echo "[step4] 等 bind mount 同步..."
sleep 2

# 防线 4：reload 前 nginx -t 校验
echo "[step4] nginx -t 校验配置..."
docker exec "${GATEWAY_CONTAINER}" nginx -t

echo "[step4] nginx -s reload..."
docker exec "${GATEWAY_CONTAINER}" nginx -s reload 2>/dev/null || true
echo "[step4] reload 完成 → 流量已切到 oneauth-${NEXT}"

# 切换成功，取消回滚标记
_SLOT_CONF_MODIFIED=false
rm -f "${SLOT_CONF_BAK}"

# ==================== Step 5: 排水 + 停旧槽 ====================
echo ""
echo "========== [步骤 5/5] 停止旧槽位 =========="
if [ "${CURRENT}" != "none" ]; then
    echo "[step5] 排水等待 ${DRAIN_WAIT}s..."
    sleep "${DRAIN_WAIT}"
    ${DC} --profile "${CURRENT}" stop "oneauth-${CURRENT}"
    ${DC} --profile "${CURRENT}" rm -f "oneauth-${CURRENT}"
    echo "[step5] oneauth-${CURRENT} 已移除"
else
    echo "[step5] 跳过（首次部署，无旧槽位）"
fi

# ==================== 完成 ====================
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
case "${DEPLOY_TYPE}" in
    first)  echo "║  ✓ 部署完成: 首次部署                                        ║" ;;
    switch) echo "║  ✓ 部署完成: 蓝绿切换 ${CURRENT} → ${NEXT}                          ║" ;;
esac
echo "║  当前生产槽位: ${NEXT}                                       ║"
WEB_PORT=$(grep '^GATEWAY_HOST_PORT=' "${ENV_FILE}" 2>/dev/null | cut -d= -f2 || echo "80")
echo "║  Gateway: http://localhost:${WEB_PORT}/                                 ║"
echo "╚════════════════════════════════════════════════════════════╝"
