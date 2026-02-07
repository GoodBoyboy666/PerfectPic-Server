#!/bin/bash

# 设置脚本在遇到错误时退出
set -e

# 进入项目根目录 (假设脚本在 script/ 目录下)
cd "$(dirname "$0")/.."

echo -e "\033[36m=========================================="
echo -e "    🛠️  Perfect Pic Server 构建脚本  📦"
echo -e "==========================================\033[0m"

# 1. 检查环境
echo -e "\n\033[33m[1/8] 🔍 正在检查环境...\033[0m"

check_command() {
    local cmd="$1"
    local name="$2"
    if command -v "$cmd" >/dev/null 2>&1; then
        local ver=""
        if [ "$cmd" = "go" ]; then
            ver=$("$cmd" version | head -n 1)
        else
            ver=$("$cmd" --version | head -n 1)
        fi
        echo -e "  [✅] $name 已安装 ($ver)"
        return 0
    else
        echo -e "  [❌] $name 未找到，请先安装。"
        return 1
    fi
}

ENV_OK=true
check_command go "Go" || ENV_OK=false
check_command node "Node.js" || ENV_OK=false
check_command pnpm "pnpm" || ENV_OK=false

if ! command -v git >/dev/null 2>&1; then
    echo -e "  [❌] Git 未找到 (脚本依赖 Git 操作)"
    ENV_OK=false
fi

if [ "$ENV_OK" = false ]; then
    echo -e "\n\033[31m❌ 环境检查失败，请安装缺失的依赖后重试。\033[0m"
    exit 1
fi

# 2. 获取构建版本
echo -e "\n\033[33m[2/8] 🏷️  获取构建版本信息...\033[0m"

# 尝试获取当前 commit 的 exact tag
if CURRENT_TAG=$(git describe --tags --exact-match HEAD 2>/dev/null); then
    BUILD_VERSION=$CURRENT_TAG
    echo -e "  ✅ 检测到当前 commit 存在 tag: \033[32m$BUILD_VERSION\033[0m"
else
    # 使用 git describe --tags --always --dirty
    BUILD_VERSION=$(git describe --tags --always --dirty)
    echo -e "  ℹ️  当前 commit 无 tag，生成版本: \033[32m$BUILD_VERSION\033[0m"
fi

BUILD_TIME=$(date '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT=$(git rev-parse HEAD)

echo "  📌 构建版本: $BUILD_VERSION"
echo "  🕒 构建时间: $BUILD_TIME"

# 3. 拉取前端代码
echo -e "\n\033[33m[3/8] 📥 准备前端代码...\033[0m"
FRONTEND_REPO_URL="https://github.com/GoodBoyboy666/perfect-pic-web.git"
WEB_DIR="web-source"

if [ -d "$WEB_DIR" ]; then
    echo "  ℹ️  目录 '$WEB_DIR' 已存在，正在更新..."
    cd "$WEB_DIR"
    git fetch --all --tags
    cd ..
else
    echo "  ℹ️  正在克隆前端仓库..."
    git clone "$FRONTEND_REPO_URL" "$WEB_DIR"
fi

# 4. 询问构建版本
echo -e "\n\033[33m[4/8] 🎯 确定前端版本...\033[0m"
cd "$WEB_DIR"

HAS_SAME_TAG=false
if git show-ref --tags --quiet refs/tags/"$BUILD_VERSION" 2>/dev/null; then
    HAS_SAME_TAG=true
fi

FRONTEND_REF=""
if [ "$HAS_SAME_TAG" = true ]; then
    echo -e "  👀 发现前端仓库存在同名 tag: \033[36m$BUILD_VERSION\033[0m"
    read -p "  👉 是否使用该 tag? (Y/n) [默认 Y]: " USE_SAME_TAG
    USE_SAME_TAG=${USE_SAME_TAG:-Y}
    if [[ "$USE_SAME_TAG" =~ ^[Yy]$ ]]; then
        FRONTEND_REF="$BUILD_VERSION"
    fi
fi

if [ -z "$FRONTEND_REF" ]; then
    echo "  👇 请输入要使用的前端版本 (分支名/Tag/Commit Hash)"
    read -p "  👉 (直接回车使用 beta 分支最新代码): " USER_INPUT
    if [ -z "$USER_INPUT" ]; then
        FRONTEND_REF="origin/beta"
        echo "  ℹ️  使用默认: beta 分支最新代码"
    else
        FRONTEND_REF="$USER_INPUT"
    fi
fi

echo "  🔄 正在签出前端版本: $FRONTEND_REF"
if ! git checkout "$FRONTEND_REF"; then
    echo -e "  \033[31m❌ 前端签出失败，请检查版本号是否正确。\033[0m"
    exit 1
fi

FRONTEND_HASH=$(git rev-parse --short HEAD)
echo -e "  ✅ 前端 Commit Hash: \033[32m$FRONTEND_HASH\033[0m"
cd ..

# 5. 编译前端
echo -e "\n\033[33m[5/8] 🏗️  编译前端...\033[0m"
cd "$WEB_DIR"

export VITE_APP_VERSION="$BUILD_VERSION"
export VITE_UI_HASH="$FRONTEND_HASH"
export VITE_BUILD_TIME="$BUILD_TIME"

echo "  📦 使用 pnpm 安装依赖..."
pnpm install --frozen-lockfile
echo "  🔨 使用 pnpm 构建..."
pnpm build

if [ $? -ne 0 ]; then
    echo -e "  \033[31m❌ 前端编译失败。\033[0m"
    exit 1
fi
cd ..

# 6. 复制前端产物
echo -e "\n\033[33m[6/8] 📋 复制前端产物...\033[0m"
FRONTEND_DEST="frontend"

rm -rf "$FRONTEND_DEST"/*
mkdir -p "$FRONTEND_DEST"

cp -r "$WEB_DIR/dist/"* "$FRONTEND_DEST/"
touch "$FRONTEND_DEST/.keep"
echo -e "  ✅ 前端产物已复制到 $FRONTEND_DEST 目录"

# 7. 编译后端
echo -e "\n\033[33m[7/8] 🚀 编译后端 (4种产物)...\033[0m"

LDFLAGS_COMMON="-s -w -X 'main.AppVersion=$BUILD_VERSION' -X 'main.BuildTime=$BUILD_TIME' -X 'main.GitCommit=$GIT_COMMIT'"
LDFLAGS_EMBED="$LDFLAGS_COMMON -X 'main.FrontendVer=$FRONTEND_HASH'"
OUTPUT_DIR="bin"
mkdir -p "$OUTPUT_DIR"

echo "  正在构建..."
export CGO_ENABLED=0

# 1. Linux Pure
echo -e "  🐧 [1/4] Building Linux AMD64 (Pure)..."
GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS_COMMON" -o "$OUTPUT_DIR/perfect-pic-server-$BUILD_VERSION-linux-amd64" .

# 2. Linux Embed
echo -e "  🐧 [2/4] Building Linux AMD64 (Embed)..."
GOOS=linux GOARCH=amd64 go build -tags embed -ldflags "$LDFLAGS_EMBED" -o "$OUTPUT_DIR/perfect-pic-server-$BUILD_VERSION-embed-linux-amd64" .

# 3. Windows Pure
echo -e "  🪟 [3/4] Building Windows AMD64 (Pure)..."
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS_COMMON" -o "$OUTPUT_DIR/perfect-pic-server-$BUILD_VERSION-windows-amd64.exe" .

# 4. Windows Embed
echo -e "  🪟 [4/4] Building Windows AMD64 (Embed)..."
GOOS=windows GOARCH=amd64 go build -tags embed -ldflags "$LDFLAGS_EMBED" -o "$OUTPUT_DIR/perfect-pic-server-$BUILD_VERSION-embed-windows-amd64.exe" .

if [ $? -ne 0 ]; then
    echo -e "  \033[31m❌ Backend compile failed.\033[0m"
    exit 1
fi

echo -e "  \033[32m✅ 后端构建成功!\033[0m"

# 8. 完成
echo -e "\n\033[32m[8/8] 🎉 构建完成!\033[0m"
echo -e "  📂 产物位置: \033[36m$OUTPUT_DIR\033[0m"

# 为 Linux 产物添加执行权限
chmod +x "$OUTPUT_DIR"/*-linux-*