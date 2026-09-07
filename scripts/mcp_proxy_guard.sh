#!/usr/bin/env bash
# MCP/skill 连通性自愈守卫（Task: MCP/skill 网络不通时自动挂代理）
# 用法: bash scripts/mcp_proxy_guard.sh [HOST...]   # HOST 缺省为 github.com registry.npmjs.org
# 行为: 探测各 HOST → 不通则依次尝试用户级/常见本地代理端口 → 成功即导出并输出 export 行；全部失败 exit 1。
set -u

DEFAULT_HOSTS="https://github.com https://registry.npmjs.org"
HOSTS="${*:-$DEFAULT_HOSTS}"

probe() {  # $1=url  ->  0=通
    curl -sI --max-time "${GUARD_TIMEOUT:-6}" -o /dev/null -w "%{http_code}" "$1" 2>/dev/null \
        | grep -qE "^[23]"
}

# 1) 已有代理环境变量 → 直接复用（不再重复探测代理本身）
if [ -n "${HTTPS_PROXY:-}" ] || [ -n "${HTTP_PROXY:-}" ]; then
    ok=1
    for h in $HOSTS; do probe "$h" || ok=0; done
    if [ "$ok" = 1 ]; then
        echo "OK: proxy env already effective (HTTPS_PROXY=${HTTPS_PROXY:-$HTTP_PROXY})"
        exit 0
    fi
fi

# 2) 无代理变量或变量无效 → 依次尝试候选本地代理端口
for port in 7897 7890 7891 10808 10809 1080 8118 8888; do
    export HTTP_PROXY="http://127.0.0.1:$port"
    export HTTPS_PROXY="http://127.0.0.1:$port"
    export ALL_PROXY="http://127.0.0.1:$port"
    ok=1
    for h in $HOSTS; do probe "$h" || ok=0; done
    if [ "$ok" = 1 ]; then
        echo "OK: auto-mounted proxy http://127.0.0.1:$port"
        echo "export HTTP_PROXY=http://127.0.0.1:$port HTTPS_PROXY=http://127.0.0.1:$port ALL_PROXY=http://127.0.0.1:$port"
        exit 0
    fi
done
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY

# 3) 直连兜底
ok=1
for h in $HOSTS; do probe "$h" || ok=0; done
if [ "$ok" = 1 ]; then
    echo "OK: direct connection works (no proxy needed)"
    exit 0
fi

echo "FAIL: all candidate proxies and direct connection failed" >&2
echo "hint: start your proxy client, or check ports 7897/7890/10808/1080" >&2
exit 1
