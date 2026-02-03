# Perfect Pic Server

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![Gin](https://img.shields.io/badge/Framework-Gin-00ADD8?style=flat)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?style=flat&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

**Perfect Pic Server** 是一个基于 Go (Gin) 开发的高性能、轻量级且功能完备的图床（图片托管）后端服务。采用**前后端分离架构**，使用AI辅助开发，专为个人或小型团队设计，提供安全可靠的图片存储、管理和分发功能。

## ✨ 核心特性

* **🚀 高性能架构**
  * **多数据库适配**: 开箱即用支持 **SQLite** (零配置)，并可无缝切换至 **MySQL** 或 **PostgreSQL** 以适应生产环境。
  * **多级缓存加速**: 结合 HTTP 静态资源缓存与服务端内存缓存策略，大幅降低数据库压力，提升响应速度。
  * **并发与稳定性**: 针对不同数据库自动调优连接池，支持高并发读写；配合优雅停机机制，保障业务处理不中断。

* **🛡️ 安全可靠**
  * **多维安全防御**: 内置 JWT 身份认证、动态 IP 限流 (Rate Limiting) 以及生产环境安全检查，有效抵御恶意攻击。
  * **深度文件校验**: 基于文件内容 (Magic Bytes) 而非后缀名识别真实文件类型，杜绝伪装文件上传风险。
  * **数据一致性**: 核心操作（如批量删除、配额扣减）采用原子事务处理，确保文件与数据库状态始终同步。

* **⚙️ 现代架构与易用性**
  * **前后端分离**: 基于标准 RESTful API 设计，逻辑解耦。同时支持将前端资源嵌入二进制文件，既享受分离开发的灵活性，又拥有“单文件部署”的便捷性。
  * **配置热重载**: 支持在线动态调整系统参数（如限流阈值、站点设置），无需重启服务。
  * **智能配额管理**: 采用增量更新策略，无论图片数量多少，都能快速计算用户剩余存储空间。
  * **规范化存储**: 自动按日期分目录存储文件，便于运维管理与备份。

## 🛠️ 技术栈

* **语言**: Go (Golang)
* **Web 框架**: [Gin](https://github.com/gin-gonic/gin)
* **ORM**: [GORM](https://gorm.io/)
* **数据库**: SQLite, MySQL, PostgreSQL
* **配置管理**: [Viper](https://github.com/spf13/viper)
* **工具库**: UUID, Captcha, Lumberjack (日志)

## 🚀 快速开始

### 1. 下载

> [!TIP]
> 带有 `embed` 字样的构建默认嵌入前端资源，开箱即用。不带该字样的构建仅为后端服务，需要自行部署前端服务。

请前往 [Releases](https://github.com/GoodBoyboy666/PerfectPic-Server/releases) 页面下载适用于您操作系统的最新版本程序。

### 2. 运行

下载后，直接在终端或命令行中运行程序。为了安全起见，生产环境**强烈建议**设置 JWT 密钥。

**Linux / macOS:**

```bash

# 赋予执行权限
chmod +x perfect-pic-server

# 设置环境变量并启动
export PERFECT_PIC_SERVER_MODE=release
export PERFECT_PIC_JWT_SECRET=your_secure_random_secret_key
./perfect-pic-server
```

**Windows (PowerShell):**

```powershell
$env:PERFECT_PIC_SERVER_MODE="release"
$env:PERFECT_PIC_JWT_SECRET="your_secure_random_secret_key"
.\perfect-pic-server.exe
```

服务启动后，默认运行在 `http://localhost:8080`。

### 3. 初始化

访问 `http://localhost:8080/init` 即可进入初始化向导。

## 🛠️ 手动构建

如果您想从源码编译或参与开发：

### 1. 环境要求

* Go 1.21 或更高版本
* MySQL/PostgreSQL (可选)

### 2. 获取代码

```bash
git clone https://github.com/GoodBoyboy666/PerfectPic-Server.git

cd perfect-pic-server
```

### 3. 获取前端代码（embed 模式）

编译前端项目 [PerfectPic-Web](https://github.com/GoodBoyboy666/PerfectPic-Web)，将编译产物复制进`frontend`目录

这将打包前端Web内容进入二进制文件

### 4. 编译运行

```bash
go mod tidy

# 开发模式运行 (默认使用 SQLite)
go run main.go

# 编译二进制文件
go build -o perfect-pic-server main.go
```

### 5. 前后端分离部署（非 embed 模式）

项目前端仓库为：[PerfectPic-Web](https://github.com/GoodBoyboy666/PerfectPic-Web)

可以将前端与后端分离部署于不同的机器，只需将来自下列的路径的请求转发至后端即可：

* /api/*
* /imgs/*
* /avatars/*

可以使用Nginx或者Caddy的反向代理处理相关请求。

## ⚙️ 配置说明

项目支持 `config.yaml` 配置文件和环境变量双重配置。

### 配置文件 (config.yaml)

首次运行会自动使用默认配置，你可以在根目录或 `config/` 目录下创建 `config.yaml`：

```yaml
server:
  port: "8080"
  mode: "release" # debug / release

database:
  type: "sqlite" # sqlite, mysql, postgres
  filename: "config/perfect_pic.db" # for sqlite
  host: "127.0.0.1" # for mysql/postgres
  port: "3306"
  user: "root"
  password: "password"
  name: "perfect_pic"

jwt:
  secret: "change_this_to_a_secure_random_string"
  expiration_hours: 24

upload:
  path: "uploads/imgs"
  url_prefix: "/imgs/"
  avatar_path: "uploads/avatars"
  avatar_url_prefix: "/avatars/"

smtp:
  host: "smtp.example.com"
  port: 587
  username: "examle@example.com"
  password: "your_smtp_password"
  from: "examle@example.com"
  ssl: false
```

### 环境变量

所有配置均可通过环境变量覆盖，前缀为 `PERFECT_PIC_`，层级用 `_` 分隔。
例如：

* `server.port` -> `PERFECT_PIC_SERVER_PORT`
* `jwt.secret` -> `PERFECT_PIC_JWT_SECRET`

## 📂 目录结构

```text
.
├── config/             # 配置文件目录
├── frontend/           # 前端静态资源 (嵌入式)
├── internal/
│   ├── config/         # 配置加载与管理
│   ├── consts/         # 常量定义
│   ├── db/             # 数据库初始化 (GORM + SQLite)
│   ├── handler/        # 业务逻辑控制器 (Controller)
│   │   └── admin/      # 管理员相关控制器
│   ├── middleware/     # Gin 中间件 (Auth, CORS, RateLimit, Cache)
│   ├── model/          # 数据库模型 (User, Image, Setting)
│   ├── router/         # 路由定义
│   ├── service/        # 核心业务逻辑服务层
│   └── utils/          # 工具函数
├── uploads/            # 图片存储目录 (自动创建)
├── main.go             # 程序入口
└── go.mod
```

## 📝 API 概览（部分）

### 公开接口

* `GET /api/init`: 检查是否需要初始化系统
* `POST /api/init`: 初始化管理员账号
* `POST /api/login`: 用户登录
* `POST /api/register`: 用户注册
* `GET /api/webinfo`: 获取站点公开信息

### 用户接口 (需 Auth)

* `POST /api/user/upload`: 上传图片
* `GET /api/user/images`: 获取我的图库
* `DELETE /api/user/images/batch`: 批量删除图片
* `GET /api/user/profile`: 获取个人信息
* `PATCH /api/user/avatar`: 更新头像

### 管理员接口 (需 Admin 权限)

* `GET /api/admin/stats`: 获取服务器统计
* `GET /api/admin/users`: 用户列表管理
* `PATCH /api/admin/settings`: 动态修改系统配置

## 🤝 贡献

欢迎提交 Issue 或 Pull Request 来改进这个项目！

## 📄 许可证

[MIT License](LICENSE)
