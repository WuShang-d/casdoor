# Casdoor 联合认证增强版 AI 服务门户

本 fork 在保留 Casdoor 原有 OAuth/OIDC 登录、用户、应用、组织管理和基础 Web UI 的基础上，新增了基于远程证明的联合认证模块。实现采用 `Casdoor IdP + Trust Orchestrator + Trust Gateway` 架构，不重写 Casdoor 登录主流程，也不把动态 attestation 强耦合进原有 access token 签发路径。

## 新增能力

- `Casdoor IdP`：继续负责用户登录、OAuth/OIDC token issuance、组织/应用管理和原有 Web UI。
- `Trust Orchestrator`：新增 trust session / trust assertion、attestation evidence 验证、`env_hash` / `cbt_digest` 计算、freshness 与 risk-aware policy 决策。
- `Trust Gateway`：新增 `/api/proxy-ai-service` 门禁入口，同时检查 Casdoor JWT、trust session 和 freshness，再代理或返回 mock AI inference 响应。
- `Mock verifier`：默认启用，无需生产级 TEE 即可完成 Milestone 1 演示；在 Trust Policy 中配置 `verifierUrl` 后可接入真实或半真实 verifier service。
- `可视化 UI`：新增 Trust Dashboard、Protected Services、Trust Policies、Attestation Records 页面。

## 新增后端对象

- `ProtectedService`：受保护 AI 服务定义，包括模型 ID、后端 endpoint、绑定 trust policy、期望 `env_hash`。
- `TrustPolicy`：risk-aware policy，默认 refresh/freshness 推荐配置为 `120s`。
- `AttestationRecord`：attestation 审计记录，记录 verifier、风险分、决策、错误码等。
- `TrustSession`：联合认证会话，保存 `env_hash`、`cbt_digest`、trust assertion、最新验证时间和 final decision。

## 新增 API

- `POST /api/init-trust-session`
- `POST /api/verify-attestation`
- `POST /api/refresh-trust-session`
- `GET /api/get-trust-status`
- `GET /api/get-attestation-records`
- `GET /api/get-protected-services`
- `GET /api/get-trust-policies`
- `POST /api/update-trust-policy`
- `POST /api/proxy-ai-service`

保留的关键错误码：

- `evidence_invalid`
- `freshness_expired`
- `risk_stepup_required`
- `trust_session_not_found`
- `service_policy_missing`

Gateway JWT 校验失败时会额外返回 `jwt_invalid`。

## 新增前端页面

- `/trust-dashboard`：展示 current user、target protected service、model id、attestation status、`env_hash`、`cbt_digest`、freshness age、risk_score、final decision、next refresh countdown、latest verification timestamp。
- `/protected-services`：查看受保护 AI 服务。
- `/trust-policies`：查看和编辑 freshness、refresh、risk threshold、verifier URL 等策略配置。
- `/attestation-records`：查看联合认证审计记录。

页面入口位于管理台 `LLM AI` 菜单下。

## 环境配置

后端：

- Go `1.25.x`，仓库 `go.mod` 指定 toolchain 为 `go1.25.8`。
- 数据库配置沿用 Casdoor 原配置文件：`conf/app.conf`。
- 启动时会通过 xorm 自动同步新增表：`protected_service`、`trust_policy`、`attestation_record`、`trust_session`。
- 首次启动会初始化默认服务 `built-in/ai-inference-default` 和默认策略 `built-in/trust-policy-default`。

前端：

- Node.js 与 Yarn，依赖定义在 `web/package.json` / `web/yarn.lock`。
- 仍使用 Casdoor 原 React + Ant Design 前端工程。

可选 verifier：

- 默认 `TrustPolicy.verifierUrl` 为空，使用内置 mock verifier。
- 如果要接入真实/半真实 verifier，在 `/trust-policies` 中设置 `Verifier URL`。
- verifier 推荐返回 JSON 字段：`status`、`envHash`、`attestedAt`、`verifiedAt`、`evidenceDigest`、`errorCode`、`errorMessage`。

## 运行方式

后端开发运行：

```bash
go run main.go
```

前端开发运行：

```bash
cd web
yarn install
yarn start
```

前端生产构建：

```bash
cd web
yarn build
```

Docker 方式仍可沿用原 Casdoor `Dockerfile` / `docker-compose.yml`，需要确保 `conf/app.conf` 中数据库连接可用。

## 联合认证演示流程

1. 启动 Casdoor 并登录。
2. 进入 `LLM AI -> Trust Dashboard`。
3. 页面会自动执行 `init-trust-session -> verify-attestation`，默认使用 mock verifier。
4. Dashboard 显示 `verified` attestation、`env_hash`、`cbt_digest`、freshness age、risk_score 和 final decision。
5. 点击 `Refresh` 可刷新 trust session，默认刷新策略为 `120s`。
6. 点击 `Gateway Test` 会调用 `/api/proxy-ai-service`，Gateway 校验 Casdoor JWT、trust session、freshness 后返回 mock AI inference 响应。

## 架构约束

- 不修改 Casdoor 原有登录主流程。
- 不把动态 attestation 直接写入 access token 作为第一阶段主路径。
- 联合认证结果通过 `TrustSession` / trust assertion 表达。
- Trust Gateway 同时检查 Casdoor JWT、trust session 和 freshness。
- freshness / refresh 默认推荐部署配置为 `120s`。
- 该实现面向阶段性交付，不追求生产级 TEE 全兼容，也不改写全局 OAuth token issuance semantics。
