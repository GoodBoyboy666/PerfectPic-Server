# 第一阶段：构建前端
FROM node:20-alpine AS frontend-builder

ARG FRONTEND_REPO="https://github.com/GoodBoyboy666/perfect-pic-web.git"
ARG FRONTEND_REF="origin/beta"
ARG APP_VERSION="v0.0.0-docker"
ARG BUILD_TIME="unknown"

WORKDIR /web-source

# 安装 git
RUN apk add --no-cache git

# 克隆并检出代码
RUN git clone ${FRONTEND_REPO} . && \
    git fetch --all --tags && \
    git checkout ${FRONTEND_REF}

# 保存前端哈希值供后端阶段使用
RUN git rev-parse --short HEAD > /frontend_hash.txt

# 设置 Vite 构建所需的环境变量
ENV VITE_APP_VERSION=${APP_VERSION}
ENV VITE_BUILD_TIME=${BUILD_TIME}

# 安装依赖并构建
# 在构建前动态设置 VITE_UI_HASH
RUN corepack enable && corepack prepare pnpm@latest --activate && \
    pnpm install --frozen-lockfile && \
    export VITE_UI_HASH=$(cat /frontend_hash.txt) && \
    pnpm build

# 第二阶段：构建后端
FROM golang:1.25-alpine AS backend-builder

WORKDIR /app

ARG APP_VERSION="v0.0.0-docker"
ARG BUILD_TIME="unknown"
ARG GIT_COMMIT="unknown"

# 安装 git (为了下载依赖)
RUN apk add --no-cache git

# 先复制 go.mod 和 go.sum 以利用层缓存
COPY go.mod go.sum ./
RUN go mod download

# 复制后端源码
COPY . .

# 复制构建好的前端资源
# 注意：我们将构建产物直接复制到 frontend 目录，这与 build.sh 中的逻辑一致
COPY --from=frontend-builder /web-source/dist ./frontend
COPY --from=frontend-builder /frontend_hash.txt ./frontend_hash.txt

# 构建后端
# 使用 -tags embed 启用嵌入功能
# 从文件可以直接读取前端版本号注入到 ldflags 中
RUN FRONTEND_VER=$(cat frontend_hash.txt) && \
    CGO_ENABLED=0 GOOS=linux go build \
    -tags embed \
    -ldflags "-s -w \
    -X 'main.AppVersion=${APP_VERSION}' \
    -X 'main.BuildTime=${BUILD_TIME}' \
    -X 'main.GitCommit=${GIT_COMMIT}' \
    -X 'main.FrontendVer=${FRONTEND_VER}'" \
    -o perfect-pic-server .

# 第三阶段：最终运行时镜像
FROM alpine:latest

WORKDIR /app

# 安装时区数据和 CA 证书
RUN apk add --no-cache tzdata ca-certificates

# 从构建阶段复制二进制文件
COPY --from=backend-builder /app/perfect-pic-server .

# 创建常用目录
RUN mkdir -p config uploads/imgs

# 暴露默认端口
EXPOSE 8080

# 运行
ENTRYPOINT ["./perfect-pic-server"]
