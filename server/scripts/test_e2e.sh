#!/usr/bin/env bash
# oneauth V0.1 端到端测试脚本
#
# 用法：
#   1. 先启动服务：./scripts/deploy-local.sh
#   2. 等服务 ready 后跑：./scripts/docker-service-manager.sh e2e   或   bash server/scripts/test_e2e.sh
#
# 验证内容：
#   - /health, /ready
#   - bootstrap admin 能登录
#   - 注册新用户 → 拿 token
#   - 登录 → 拿 token
#   - 用 access_token 调 /api/me
#   - refresh_token 换新 token
#   - 旧 refresh 重放检测
#   - logout 后 access_token 进入黑名单

set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
ADMIN_EMAIL="${BOOTSTRAP_ADMIN_EMAIL:-admin@oneauth.local}"
ADMIN_PASSWORD="${BOOTSTRAP_ADMIN_PASSWORD:-ChangeMeOnFirstLogin!}"

PASS=0
FAIL=0

# ---- helpers ----

color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
green() { color "32" "$1"; }
red()   { color "31" "$1"; }
yellow(){ color "33" "$1"; }
bold()  { color "1"  "$1"; }

step() {
  echo
  echo "$(bold "=== $1 ===")"
}

ok() {
  echo "  $(green "✓") $1"
  PASS=$((PASS+1))
}

fail() {
  echo "  $(red "✗") $1"
  FAIL=$((FAIL+1))
}

# Extract field from JSON without jq dependency:
#   json_field "<JSON>" "field_name"
json_field() {
  echo "$1" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('$2', ''))"
}

# Make a request and split status/body
# Usage: req METHOD PATH [DATA] [BEARER_TOKEN]
req() {
  local method="$1" path="$2" data="${3:-}" token="${4:-}"
  local url="${BASE_URL}${path}"
  local headers=(-H "Content-Type: application/json")
  if [ -n "$token" ]; then
    headers+=(-H "Authorization: Bearer $token")
  fi
  if [ -n "$data" ]; then
    curl -sS -o /tmp/oneauth_e2e_body.json -w "%{http_code}" -X "$method" \
      "${headers[@]}" --data "$data" "$url"
  else
    curl -sS -o /tmp/oneauth_e2e_body.json -w "%{http_code}" -X "$method" \
      "${headers[@]}" "$url"
  fi
}

# ---- 等服务 ready ----

step "Step 0: 等待服务 ready"
for i in $(seq 1 30); do
  if curl -fsS "${BASE_URL}/ready" >/dev/null 2>&1; then
    ok "service is ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    fail "service not ready after 30s"
    echo "  请先 ./scripts/docker-service-manager.sh up，并等待 mysql 完成 migration"
    exit 1
  fi
  sleep 1
done

# ---- /health /ready ----

step "Step 1: /health, /ready"
status=$(req GET /health)
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then ok "/health 200"; else fail "/health $status: $body"; fi

status=$(req GET /ready)
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then ok "/ready 200"; else fail "/ready $status: $body"; fi

# ---- Bootstrap admin 登录 ----

step "Step 2: bootstrap admin 登录"
status=$(req POST /api/auth/login \
  "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then
  ok "admin login 200"
  ADMIN_TOKEN=$(json_field "$body" access_token)
  ADMIN_REFRESH=$(json_field "$body" refresh_token)
  ADMIN_ID=$(json_field "$body" user_id)
  echo "  user_id=$ADMIN_ID"
else
  fail "admin login $status: $body"
fi

# ---- 注册新用户 ----

step "Step 3: 注册新用户"
TIMESTAMP=$(date +%s)
TEST_EMAIL="test_${TIMESTAMP}@example.com"
TEST_PASSWORD="TestPassword123!"
status=$(req POST /api/auth/register \
  "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\",\"nickname\":\"测试用户\"}")
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "201" ]; then
  ok "register 201"
  USER_TOKEN=$(json_field "$body" access_token)
  USER_REFRESH=$(json_field "$body" refresh_token)
  USER_ID=$(json_field "$body" user_id)
  echo "  user_id=$USER_ID  email=$TEST_EMAIL"
else
  fail "register $status: $body"
fi

# 重复注册应失败
status=$(req POST /api/auth/register \
  "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
if [ "$status" = "409" ]; then
  ok "duplicate register rejected (409)"
else
  fail "duplicate register expected 409, got $status"
fi

# ---- 登录新用户 ----

step "Step 4: 登录新用户"
status=$(req POST /api/auth/login \
  "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then
  ok "user login 200"
else
  fail "user login $status: $body"
fi

# 错误密码
status=$(req POST /api/auth/login \
  "{\"email\":\"$TEST_EMAIL\",\"password\":\"WrongPassword!\"}")
if [ "$status" = "401" ]; then
  ok "wrong password rejected (401)"
else
  fail "wrong password expected 401, got $status"
fi

# ---- 受保护接口 ----

step "Step 5: GET /api/me"
status=$(req GET /api/me "" "$USER_TOKEN")
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then
  returned_id=$(json_field "$body" user_id)
  if [ "$returned_id" = "$USER_ID" ]; then
    ok "/api/me returns matching user_id (ULID, not BIGINT)"
  else
    fail "/api/me user_id mismatch: $returned_id vs $USER_ID"
  fi
else
  fail "/api/me $status: $body"
fi

# 无 token
status=$(req GET /api/me)
if [ "$status" = "401" ]; then
  ok "/api/me without token rejected (401)"
else
  fail "/api/me without token expected 401, got $status"
fi

# 假 token
status=$(req GET /api/me "" "fake.jwt.token")
if [ "$status" = "401" ]; then
  ok "/api/me with fake token rejected (401)"
else
  fail "/api/me with fake token expected 401, got $status"
fi

# ---- Refresh token ----

step "Step 6: refresh token (rotation)"
status=$(req POST /api/auth/refresh \
  "{\"refresh_token\":\"$USER_REFRESH\"}")
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then
  ok "refresh 200"
  USER_TOKEN_2=$(json_field "$body" access_token)
  USER_REFRESH_2=$(json_field "$body" refresh_token)
  if [ "$USER_REFRESH_2" != "$USER_REFRESH" ]; then
    ok "new refresh_token differs from old (rotation)"
  else
    fail "refresh_token did not rotate"
  fi
else
  fail "refresh $status: $body"
fi

# ---- 重放检测 ----

step "Step 7: 旧 refresh_token 重放检测"
status=$(req POST /api/auth/refresh \
  "{\"refresh_token\":\"$USER_REFRESH\"}")
if [ "$status" = "401" ]; then
  ok "old refresh_token rejected (replay detected, 401)"
else
  body=$(cat /tmp/oneauth_e2e_body.json)
  fail "old refresh_token expected 401, got $status: $body"
fi

# 整 family 应已撤销，新 refresh 也无法用
status=$(req POST /api/auth/refresh \
  "{\"refresh_token\":\"$USER_REFRESH_2\"}")
if [ "$status" = "401" ]; then
  ok "family-revoked refresh_token also rejected"
else
  body=$(cat /tmp/oneauth_e2e_body.json)
  fail "family-revoked refresh expected 401, got $status: $body"
fi

# ---- logout ----

step "Step 8: logout 把 access_token 加入黑名单"
# 重新登录拿一对干净的 token
status=$(req POST /api/auth/login \
  "{\"email\":\"$TEST_EMAIL\",\"password\":\"$TEST_PASSWORD\"}")
body=$(cat /tmp/oneauth_e2e_body.json)
USER_TOKEN_3=$(json_field "$body" access_token)

status=$(req POST /api/auth/logout "" "$USER_TOKEN_3")
if [ "$status" = "200" ]; then
  ok "logout 200"
else
  fail "logout $status"
fi

# 登出后用同一 access_token 调受保护接口应 401
status=$(req GET /api/me "" "$USER_TOKEN_3")
if [ "$status" = "401" ]; then
  ok "access_token after logout rejected (blocklist works)"
else
  fail "access_token after logout expected 401, got $status"
fi

# ---- OAuth Authorization Code + PKCE 流程（V0.2 新增） ----

step "Step 9: OAuth Authorization Code + PKCE 完整流程"

# 拿 admin_web 的 client_secret —— bootstrap 时从日志读
CLIENT_ID="admin_web"
CLIENT_SECRET=$(docker compose logs oneauth 2>/dev/null \
  | grep "client_secret =" | head -1 | sed -E 's/.*client_secret = ([^ ]+).*/\1/')
if [ -z "$CLIENT_SECRET" ]; then
  fail "could not read admin_web client_secret from logs (try: ./scripts/docker-service-manager.sh reset)"
  echo "  Skipping OAuth tests..."
else
  ok "found admin_web client_secret in logs"

  REDIRECT_URI="http://localhost:8080/oauth/callback/admin"

  # 生成 PKCE pair
  CODE_VERIFIER=$(openssl rand -base64 64 | tr -d "=+/\n" | cut -c1-43)
  CODE_CHALLENGE=$(printf "%s" "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr -d "=" | tr "/+" "_-")

  # POST /login 拿 cookie
  COOKIES=$(mktemp)
  status=$(curl -sS -c "$COOKIES" -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/login" \
    -d "email=$ADMIN_EMAIL" -d "password=$ADMIN_PASSWORD" -d "return_to=")
  if [ "$status" = "302" ]; then
    ok "POST /login 302 (cookie set)"
  else
    fail "POST /login expected 302, got $status"
  fi
  if grep -q oneauth_sid "$COOKIES"; then
    ok "oneauth_sid cookie issued"
  else
    fail "no oneauth_sid cookie"
  fi

  # GET /oauth/authorize → 302 redirect 带 code
  REDIRECT_URI_ENC=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$REDIRECT_URI', safe=''))")
  AUTHORIZE_URL="${BASE_URL}/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI_ENC}&response_type=code&state=test_state_xyz&scope=openid+profile&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"
  LOC=$(curl -sS -b "$COOKIES" -o /dev/null -w "%{redirect_url}" "$AUTHORIZE_URL")
  if echo "$LOC" | grep -q "code="; then
    ok "/oauth/authorize 302 with code"
  else
    fail "/oauth/authorize did not return code: $LOC"
  fi

  # 检查 state 原样回传
  if echo "$LOC" | grep -q "state=test_state_xyz"; then
    ok "state preserved in redirect"
  else
    fail "state not in redirect"
  fi

  CODE=$(echo "$LOC" | sed -E 's/.*[?&]code=([^&]+).*/\1/')

  # POST /oauth/token 用 code 换 token
  RESP=$(curl -sS -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=authorization_code" \
    -d "code=$CODE" \
    -d "redirect_uri=$REDIRECT_URI" \
    -d "client_id=$CLIENT_ID" \
    -d "client_secret=$CLIENT_SECRET" \
    -d "code_verifier=$CODE_VERIFIER")
  OAUTH_TOKEN=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  if [ -n "$OAUTH_TOKEN" ]; then
    ok "/oauth/token returned access_token"
  else
    fail "/oauth/token failed: $RESP"
  fi

  # 用 token 调受保护接口
  status=$(req GET /api/me "" "$OAUTH_TOKEN")
  if [ "$status" = "200" ]; then
    body=$(cat /tmp/oneauth_e2e_body.json)
    cid=$(json_field "$body" client_id)
    if [ "$cid" = "admin_web" ]; then
      ok "/api/me with OAuth token works (client_id=admin_web)"
    else
      fail "/api/me client_id mismatch: $cid"
    fi
  else
    fail "/api/me with OAuth token: $status"
  fi

  # code 重放检测
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=authorization_code" -d "code=$CODE" -d "redirect_uri=$REDIRECT_URI" \
    -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET" -d "code_verifier=$CODE_VERIFIER")
  if [ "$status" = "400" ]; then
    ok "code replay rejected (400 invalid_grant)"
  else
    fail "code replay expected 400, got $status"
  fi

  # 错误 PKCE verifier 检测（拿新 code）
  curl -sS -c "$COOKIES" -o /dev/null -X POST "${BASE_URL}/login" \
    -d "email=$ADMIN_EMAIL" -d "password=$ADMIN_PASSWORD" -d "return_to="
  LOC2=$(curl -sS -b "$COOKIES" -o /dev/null -w "%{redirect_url}" "$AUTHORIZE_URL")
  CODE2=$(echo "$LOC2" | sed -E 's/.*[?&]code=([^&]+).*/\1/')
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=authorization_code" -d "code=$CODE2" -d "redirect_uri=$REDIRECT_URI" \
    -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET" -d "code_verifier=WRONG_VERIFIER")
  if [ "$status" = "400" ]; then
    ok "wrong PKCE verifier rejected (400)"
  else
    fail "wrong PKCE expected 400, got $status"
  fi

  # 错误 client_secret
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=authorization_code" -d "code=anycode" -d "redirect_uri=$REDIRECT_URI" \
    -d "client_id=$CLIENT_ID" -d "client_secret=WRONG_SECRET" -d "code_verifier=any")
  if [ "$status" = "401" ]; then
    ok "wrong client_secret rejected (401)"
  else
    fail "wrong client_secret expected 401, got $status"
  fi

  # /oauth/authorize 用 invalid client_id（不应 redirect，应 401）
  status=$(curl -sS -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/oauth/authorize?client_id=nonexistent&redirect_uri=${REDIRECT_URI_ENC}&response_type=code&state=x&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256")
  if [ "$status" = "401" ]; then
    ok "invalid client_id rejected without redirect (401)"
  else
    fail "invalid client_id expected 401, got $status"
  fi

  # /oauth/authorize 用 invalid redirect_uri（不应 redirect，应 400）
  BAD_URI=$(python3 -c "import urllib.parse;print(urllib.parse.quote('https://attacker.example.com/', safe=''))")
  status=$(curl -sS -o /dev/null -w "%{http_code}" \
    "${BASE_URL}/oauth/authorize?client_id=${CLIENT_ID}&redirect_uri=${BAD_URI}&response_type=code&state=x&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256")
  if [ "$status" = "400" ]; then
    ok "invalid redirect_uri rejected without redirect (400)"
  else
    fail "invalid redirect_uri expected 400, got $status"
  fi

  rm -f "$COOKIES"
fi

# ---- OIDC + 协议端点（V0.2.1 新增） ----

step "Step 10: OIDC discovery + JWKS"
status=$(req GET /.well-known/openid-configuration)
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then
  ok "/.well-known/openid-configuration 200"
  for field in issuer authorization_endpoint token_endpoint userinfo_endpoint jwks_uri revocation_endpoint introspection_endpoint; do
    if echo "$body" | python3 -c "import sys,json;sys.exit(0 if json.load(sys.stdin).get('$field') else 1)"; then
      ok "  has '$field'"
    else
      fail "  missing '$field'"
    fi
  done
else
  fail "/.well-known/openid-configuration $status"
fi

status=$(req GET /.well-known/jwks.json)
body=$(cat /tmp/oneauth_e2e_body.json)
if [ "$status" = "200" ]; then
  ok "/.well-known/jwks.json 200"
  if echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
keys = d.get('keys', [])
if not keys: sys.exit(1)
k = keys[0]
need = ['kty', 'kid', 'use', 'alg', 'n', 'e']
sys.exit(0 if all(f in k for f in need) else 1)
"; then
    ok "  JWKS has well-formed RSA key (kty/kid/use/alg/n/e)"
  else
    fail "  JWKS key missing fields: $body"
  fi
else
  fail "/.well-known/jwks.json $status"
fi

# ---- id_token 颁发（OIDC scope=openid） ----

step "Step 11: id_token + /oauth/userinfo"
if [ -n "$CLIENT_SECRET" ]; then
  CODE_VERIFIER=$(openssl rand -base64 64 | tr -d "=+/\n" | cut -c1-43)
  CODE_CHALLENGE=$(printf "%s" "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr -d "=" | tr "/+" "_-")
  COOKIES=$(mktemp)
  curl -sS -c "$COOKIES" -o /dev/null -X POST "${BASE_URL}/login" \
    -d "email=$ADMIN_EMAIL" -d "password=$ADMIN_PASSWORD" -d "return_to="

  # scope=openid+profile+email + nonce
  NONCE="nonce_$(date +%s)"
  AUTHZ_URL="${BASE_URL}/oauth/authorize?client_id=admin_web&redirect_uri=${REDIRECT_URI_ENC}&response_type=code&state=oidc_test&scope=openid+profile+email&nonce=${NONCE}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"
  LOC=$(curl -sS -b "$COOKIES" -o /dev/null -w "%{redirect_url}" "$AUTHZ_URL")
  CODE=$(echo "$LOC" | sed -E 's/.*[?&]code=([^&]+).*/\1/')

  RESP=$(curl -sS -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=authorization_code" -d "code=$CODE" \
    -d "redirect_uri=$REDIRECT_URI" -d "client_id=admin_web" \
    -d "client_secret=$CLIENT_SECRET" -d "code_verifier=$CODE_VERIFIER")
  ID_TOKEN=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id_token',''))" 2>/dev/null)
  ACCESS=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
  if [ -n "$ID_TOKEN" ]; then
    ok "id_token returned (scope=openid)"
    # 解码 id_token payload 看 nonce
    PAYLOAD=$(echo "$ID_TOKEN" | cut -d. -f2 | tr "_-" "/+")
    # 补 padding
    case $((${#PAYLOAD} % 4)) in 2) PAYLOAD="${PAYLOAD}==" ;; 3) PAYLOAD="${PAYLOAD}=" ;; esac
    DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null || echo "{}")
    if echo "$DECODED" | python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit(0 if d.get('nonce')=='$NONCE' else 1)" 2>/dev/null; then
      ok "id_token preserves nonce"
    else
      fail "id_token nonce mismatch: $DECODED"
    fi
    if echo "$DECODED" | python3 -c "import sys,json;d=json.load(sys.stdin);sys.exit(0 if d.get('email') else 1)" 2>/dev/null; then
      ok "id_token includes email (scope=email)"
    else
      fail "id_token missing email"
    fi
  else
    fail "id_token missing in response: $RESP"
  fi

  # /oauth/userinfo
  status=$(req GET /oauth/userinfo "" "$ACCESS")
  body=$(cat /tmp/oneauth_e2e_body.json)
  if [ "$status" = "200" ]; then
    sub=$(json_field "$body" sub)
    if [ -n "$sub" ]; then
      ok "/oauth/userinfo returns sub (ULID): $sub"
    else
      fail "/oauth/userinfo missing sub"
    fi
  else
    fail "/oauth/userinfo $status: $body"
  fi

  # /oauth/userinfo without token
  status=$(req GET /oauth/userinfo)
  if [ "$status" = "401" ]; then
    ok "/oauth/userinfo without token rejected (401)"
  else
    fail "/oauth/userinfo without token expected 401, got $status"
  fi

  rm -f "$COOKIES"
fi

# ---- introspect / revoke ----

step "Step 12: /oauth/introspect"
if [ -n "$CLIENT_SECRET" ] && [ -n "$ACCESS" ]; then
  RESP=$(curl -sS -X POST "${BASE_URL}/oauth/introspect" \
    -d "token=$ACCESS" -d "client_id=admin_web" -d "client_secret=$CLIENT_SECRET")
  active=$(json_field "$RESP" active)
  if [ "$active" = "True" ]; then
    ok "introspect: active=true for valid token"
  else
    fail "introspect: expected active=true, got: $RESP"
  fi
  # 错误 client_secret
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/oauth/introspect" \
    -d "token=$ACCESS" -d "client_id=admin_web" -d "client_secret=WRONG")
  if [ "$status" = "401" ]; then
    ok "introspect with wrong secret rejected (401)"
  else
    fail "introspect wrong secret expected 401, got $status"
  fi
fi

step "Step 13: /oauth/revoke"
if [ -n "$CLIENT_SECRET" ] && [ -n "$ACCESS" ]; then
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/oauth/revoke" \
    -d "token=$ACCESS" -d "token_type_hint=access_token" \
    -d "client_id=admin_web" -d "client_secret=$CLIENT_SECRET")
  if [ "$status" = "200" ]; then
    ok "revoke 200 (RFC 7009)"
  else
    fail "revoke expected 200, got $status"
  fi
  # 用已撤销的 token 调 /api/me
  status=$(req GET /api/me "" "$ACCESS")
  if [ "$status" = "401" ]; then
    ok "revoked access_token rejected by /api/me"
  else
    fail "revoked token expected 401, got $status"
  fi
  # introspect 也应该 active=false
  RESP=$(curl -sS -X POST "${BASE_URL}/oauth/introspect" \
    -d "token=$ACCESS" -d "client_id=admin_web" -d "client_secret=$CLIENT_SECRET")
  active=$(json_field "$RESP" active)
  if [ "$active" = "False" ]; then
    ok "introspect: active=false for revoked token"
  else
    fail "introspect after revoke: $RESP"
  fi
fi

# ---- client_credentials grant ----

step "Step 14: grant_type=client_credentials (service token)"
SVC_SECRET=$(docker compose logs oneauth 2>/dev/null \
  | grep -A 1 "client_id     = internal_service" | grep "client_secret" | sed -E 's/.*client_secret = ([^ ]+).*/\1/' | head -1)
if [ -z "$SVC_SECRET" ]; then
  fail "could not read internal_service secret from logs"
else
  ok "found internal_service client_secret"
  RESP=$(curl -sS -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=internal_service" -d "client_secret=$SVC_SECRET" \
    -d "scope=internal.user.read")
  SVC_TOKEN=$(json_field "$RESP" access_token)
  if [ -n "$SVC_TOKEN" ]; then
    ok "service token issued"
  else
    fail "service token failed: $RESP"
  fi

  # service token 的 sub 应该是 client_id（不是 user public_id）
  PAYLOAD=$(echo "$SVC_TOKEN" | cut -d. -f2 | tr "_-" "/+")
  case $((${#PAYLOAD} % 4)) in 2) PAYLOAD="${PAYLOAD}==" ;; 3) PAYLOAD="${PAYLOAD}=" ;; esac
  DECODED=$(echo "$PAYLOAD" | base64 -d 2>/dev/null || echo "{}")
  sub=$(echo "$DECODED" | python3 -c "import sys,json;print(json.load(sys.stdin).get('sub',''))" 2>/dev/null)
  if [ "$sub" = "internal_service" ]; then
    ok "service token sub=client_id (internal_service)"
  else
    fail "service token sub mismatch: $sub"
  fi

  # 应该不返回 refresh_token
  rt=$(json_field "$RESP" refresh_token)
  if [ -z "$rt" ]; then
    ok "service token does not include refresh_token (correct)"
  else
    fail "service token should not have refresh_token"
  fi

  # 越权 scope
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=internal_service" -d "client_secret=$SVC_SECRET" \
    -d "scope=user:write")
  if [ "$status" = "400" ]; then
    ok "service token rejects out-of-allowed scope"
  else
    fail "out-of-allowed scope expected 400, got $status"
  fi

  # admin_web 不允许 client_credentials
  status=$(curl -sS -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/oauth/token" \
    -d "grant_type=client_credentials" \
    -d "client_id=admin_web" -d "client_secret=$CLIENT_SECRET" \
    -d "scope=internal.user.read")
  if [ "$status" = "401" ]; then
    ok "admin_web client cannot use client_credentials grant"
  else
    fail "admin_web client_credentials expected 401, got $status"
  fi
fi

# ---- 防爆破限流 ----

step "Step 15: API 防爆破限流（/api/auth/login 同账号多次失败 → 锁定）"
LOCK_EMAIL="lock_$(date +%s)@example.com"
# 先注册一个用户
status=$(req POST /api/auth/register \
  "{\"email\":\"$LOCK_EMAIL\",\"password\":\"CorrectPwd123\"}")
[ "$status" = "201" ] && ok "registered $LOCK_EMAIL" || fail "register lock test user: $status"

# 故意输错 5 次
locked=0
for i in 1 2 3 4 5; do
  status=$(req POST /api/auth/login \
    "{\"email\":\"$LOCK_EMAIL\",\"password\":\"wrong${i}\"}")
  if [ "$status" = "429" ]; then
    locked=1
    break
  fi
done

# 第 6 次（如果前面还没锁，这次必锁）
status=$(req POST /api/auth/login \
  "{\"email\":\"$LOCK_EMAIL\",\"password\":\"wrong6\"}")
if [ "$status" = "429" ]; then
  ok "account locked after threshold (429 returned)"
else
  fail "expected 429 after 5 failed attempts, got $status"
fi

# 锁定窗口内即使密码正确也应该 429（被锁了）
status=$(req POST /api/auth/login \
  "{\"email\":\"$LOCK_EMAIL\",\"password\":\"CorrectPwd123\"}")
if [ "$status" = "429" ]; then
  ok "correct password during lockout still rejected"
else
  fail "expected 429 even with correct password during lockout, got $status"
fi

# ---- HTML 登录页防爆破（V0.2.2 新增 P0-A 修复）----

step "Step 16: HTML 表单 /login 也要走防爆破（P0-A 修复验证）"
HLOCK_EMAIL="hlock_$(date +%s)@example.com"
# 注册新账号（API 走 register；表单 /login 不提供注册）
status=$(req POST /api/auth/register \
  "{\"email\":\"$HLOCK_EMAIL\",\"password\":\"CorrectPwd123\"}")
[ "$status" = "201" ] && ok "registered $HLOCK_EMAIL" || fail "register hlock test user: $status"

# 故意用 HTML 表单 POST 输错 5 次
hlocked=0
for i in 1 2 3 4 5; do
  hstatus=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode "email=$HLOCK_EMAIL" \
    --data-urlencode "password=wrong${i}" \
    "${BASE_URL}/login")
  # /login 失败时返回 401（render 登录页 + Unauthorized 状态）
  if [ "$hstatus" = "401" ]; then
    hlocked=1
  fi
done

# 第 6 次：账号应已被锁，即使错密码继续提交也应 401（锁定窗口内 ErrTooManyAttempts → 文案提示）
hstatus=$(curl -sS -o /tmp/oneauth_e2e_body.html -w "%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "email=$HLOCK_EMAIL" \
  --data-urlencode "password=wrong6" \
  "${BASE_URL}/login")
if [ "$hstatus" = "401" ]; then
  ok "html /login 6th attempt rejected (status 401)"
else
  fail "expected 401 on html /login 6th attempt, got $hstatus"
fi

# 验证锁定文案出现在 HTML 响应里（"登录失败次数过多"）
if grep -q "登录失败次数过多" /tmp/oneauth_e2e_body.html 2>/dev/null; then
  ok "html /login shows lockout message after threshold"
else
  fail "expected html /login lockout message in body"
fi

# 即使密码正确，锁定窗口内也应被拒（验证防爆破覆盖 HTML 表单路径）
hstatus=$(curl -sS -o /dev/null -w "%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "email=$HLOCK_EMAIL" \
  --data-urlencode "password=CorrectPwd123" \
  "${BASE_URL}/login")
if [ "$hstatus" = "401" ]; then
  ok "html /login: correct password rejected during lockout (P0-A 防爆破覆盖 HTML 路径)"
else
  fail "expected html /login 401 even with correct password during lockout, got $hstatus"
fi

# ---- 总结 ----

echo
echo "$(bold "===== Summary =====")"
echo "  Passed: $(green "$PASS")"
echo "  Failed: $(red "$FAIL")"

if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
echo "  $(green "All tests passed.")"
exit 0
