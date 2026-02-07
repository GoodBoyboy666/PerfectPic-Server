# 贡献指南 (Contributing Guide)

感谢你对 **perfect-pic-server** 的关注！我们非常欢迎任何形式的贡献，无论是修复 Bug、添加新功能，还是改进文档。

为了确保协作顺利，请遵循以下指南。

## 🤝 如何贡献

### 1. 提交 Issue (Reporting Issues)

如果你发现了 Bug 或有好的功能建议，请首先：

- 搜索现有的 [Issues](https://github.com/GoodBoyboy666/perfect-pic-server/issues)，看看是否已经有人提出。
- 如果没有，请创建一个新的 Issue。请尽量详细描述问题复现步骤或功能需求。

### 2. 提交 Pull Request (Pull Requests)

如果你想直接修改代码：

1. **Fork** 本仓库到你的 GitHub 账户。
2. **Clone** 你的 Fork 版本到本地：

   ```bash
   git clone https://github.com/你的用户名/perfect-pic-server.git
   ```

3. 在beta分支上创建一个新的开发分支：

   ```bash
   git checkout -b feature/你的新功能 beta
   # 或者
   git checkout -b fix/修复的问题 beta
   ```

4. 进行代码修改，并确保通过了所有测试。
5. 提交更改（Commit）：

   ```bash
   git commit -m "feat: 添加了xx功能"
   # 或
   git commit -m "fix: 修复了xx bug"
   ```

   > 推荐使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范。
6. 推送（Push）到你的远程仓库：

   ```bash
   git push origin feature/你的新功能
   ```

7. 在 GitHub 上提交 **Pull Request (PR)** 到 `beta` 分支。
   - 请填写 PR 模板中的所有相关信息。
   - 我们的团队会尽快进行 Code Review。

## 💻 开发环境指南

本项目基于 **Go** 语言开发。

1. **环境依赖**：
   - Go 1.25+
   - 数据库 (SQLite/MySQL/PostgreSQL，根据配置)

2. **本地运行**：

   ```bash
   # 下载依赖
   go mod download

   # 运行项目
   go run main.go
   ```

3. **代码风格**：
   - 请确保代码使用 `gofmt` 或 `goimports` 进行了格式化。
   - 运行 Linter (`golangci-lint`) 检查潜在问题。

## 📜 行为准则 (Code of Conduct)

请保持友好、尊重和包容。我们希望构建一个积极的开源社区。

## 📄 许可证

参与本项目即表示你同意你的贡献将遵循项目的 [LICENSE](LICENSE) 协议。
