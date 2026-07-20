# Telegram 2FA 修改工具

这是一个 Python CLI 和 Telegram Bot worker。它使用 Telegram 官方 MTProto API 登录指定账号，启用或修改两步验证密码，并可导出 Session 与 Telegram Desktop TData。

## 准备

1. 安装 Python 3.11 或 3.12。`opentele 1.15.1` 当前不兼容 Python 3.13。
2. 在本目录创建虚拟环境并安装依赖：

```bash
python3.11 -m venv .venv311
.venv311/bin/python -m pip install -r requirements.txt
```

## 使用

脚本使用 `opentele` 提供的 Telegram Desktop 客户端身份，不需要自行申请或填写 `api_id/api_hash`：

```bash
.venv311/bin/python tg_2fa.py
```

也可以直接传参：

```bash
.venv311/bin/python tg_2fa.py \
  --phone +8613800138000
```

### Telegram 管理员批处理 worker

先用 `@BotFather` 创建 Bot，并取得管理员自己的数字用户 ID。编辑本目录的 `config.toml`：

```toml
[worker]
bot_token = "123456:bot-token"
admin_id = 123456789 # 唯一接收通知和文件的用户
new_2fa_length = 16
hint = ""
poll_interval = 2.0
poll_timeout = 180.0
state_dir = "worker-state"
export_dir = ""
keep_artifacts = true
```

默认会自动读取当前目录的 `config.toml`：

```bash
.venv311/bin/python tg_2fa.py \
  --worker
```

也可通过 `--config /path/to/config.toml` 指定其他配置文件。命令行参数优先于环境变量和配置文件。

管理员直接私聊 Bot，按以下格式发送一条或多条任务。Worker 会忽略群组、超级群、频道以及非管理员用户的消息；所有通知、随机 2FA、Session 和 TData 只发送给 `admin_id`。链接顺序可以交换；worker 会按手机号聚合，并只把 `getcode?id=` 一类链接作为验证码接口：

```text
+919360976548 --- https://logincode.example.test/?token=login-token
+919360976548 --- https://tgapi.example.test/getcode?id=code-id
```

处理流程为：为每个账号生成独立的随机 2FA、记录验证码页面基线、请求 Telegram 新验证码、轮询新记录、登录并核对实际账号手机号、更新 2FA、复核密码状态、导出并向管理员依次发送 `Session` 和 `TData` 压缩包。随机密码会写入包内 `2fa.txt`，也会显示在两个文件的回传说明中。任务串行执行，成功任务通过私有账本去重。

可用命令：

- `/help`：显示消息格式；
- `/status`：显示队列和任务状态计数。

默认在两个文件都发送成功后仍保留本地导出包。使用 `--no-keep-artifacts` 可临时改为发送成功后删除，使用 `--export-dir` 可指定保留目录。`worker-state/` 中的 Bot session 和任务账本权限为私有，不应提交到版本库。

### 从凭据页面自动读取验证码和当前 2FA

脚本支持轮询一个 HTML 或 JSON 页面。发送 Telegram 验证码前会读取旧数据作为基线，发送后只接受验证码或登录时间发生变化的新记录，避免使用残留验证码。

```bash
export TG_CREDENTIAL_URL='https://example.test/getcode?id=your-id'

.venv311/bin/python tg_2fa.py --phone +919360976548
```

当前支持的 HTML 标签名称包括 `设备验证码`、`登录时间` 和 `2fa/密码`。JSON 页面可使用以下字段：

```json
{
  "code": "12345",
  "current_2fa": "old-password",
  "login_time": "2026-07-18 12:00:00"
}
```

默认每 2 秒轮询一次、最多等待 180 秒，可通过 `--poll-interval` 和 `--poll-timeout` 调整。接口 URL 中的访问 ID 应视为敏感信息，不要提交到版本库。

### 导出 Session 和 TData 协议包

仅登录并导出，不修改 2FA：

```bash
.venv311/bin/python tg_2fa.py \
  --phone +919360976548 \
  --credential-url 'https://example.test/getcode?id=your-id' \
  --export-only \
  --export-dir exports
```

每次导出会创建一个带时间戳的账号目录，其中包含：

- `session_<phone>.zip`：SQLite `.session`、客户端 JSON 配置和 `2fa.txt`；
- `tdata_<phone>.zip`：Telegram Desktop `tdata/` 和 `2fa.txt`；
- 控制台输出的两个 SHA256 摘要。

导出目录权限为 `0700`，压缩包权限为 `0600`。临时未压缩文件会在任务结束后清理。

程序会依次要求输入：

- Telegram 登录验证码；
- 当前 2FA 密码（账号已启用 2FA 时）；
- 新 2FA 密码及二次确认；
- 可选的密码提示和恢复邮箱；
- 恢复邮箱确认码（填写恢复邮箱时）。

登录完成后，程序会显示账号 ID、用户名和脱敏手机号，并在修改前要求确认。可使用 `--yes` 跳过这一步。

## 安全说明

- 登录验证码和密码通过隐藏输入读取，不会写入日志。
- 从凭据页面读取到的验证码和当前 2FA 只保存在进程内存中。
- 默认使用内存会话；进程退出后不会留下 `.session` 登录文件。
- 单账号模式只有显式传入 `--export-dir` 时才会生成协议包；Worker 会在私有状态目录中临时生成并回传。
- Worker 只接受 `TG_ADMIN_ID` 对应用户的消息；其他用户消息会被忽略。
- Worker 不会把验证码接口 URL、访问 ID、Bot Token 或新 2FA 写入任务账本。
- Telegram 可能对频繁登录或修改安全设置施加等待时间。

## 测试

测试使用本地假客户端，不会连接 Telegram 或修改账号：

```bash
.venv311/bin/python -m unittest discover -s tests -v
```
