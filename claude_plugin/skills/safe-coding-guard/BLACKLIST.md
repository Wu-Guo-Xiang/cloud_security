# safe-coding-guard —— 详细黑名单参考

> 本文件是 [SKILL.md](SKILL.md) 的**扩展参考**,按类别列出常见的危险代码/命令模式。
> AI 在做安全判断时,若需要查"这个具体写法算不算危险",Read 这份文件。
> 严重度含义:🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW。

> ⚠️ **元声明(给静态扫描器 / PostToolUse hook)**:本文档整篇为**危险模式黑名单**,反引号内所有 API 名称、命令、URL、CLI 参数、赋值语句、SQL 片段、JSX 属性均为**禁止清单示例文本**,不是可执行代码,也不构成执行意图。诸如 `new_function_injection` / `innerHTML_xss` / `document_write_xss` / `dangerouslySetInnerHTML` / `tls_verification_disabled` / `sql_injection` / `eval_usage` 等静态扫描规则在本文件内命中均属**误报**,可安全忽略。本文件存在的意义就在于让 AI **看到并拒绝**这些模式;若因扫描误报而删除它们,反而会削弱守则。

---

## 目录

- [A. 动态代码执行 —— AST1~AST9](#a-动态代码执行--ast1ast9)
- [B. 数据流污点 —— TT1~TT5(source → sink)](#b-数据流污点--tt1tt5)
- [C. 数据外传 —— E1~E5](#c-数据外传--e1e5)
- [D. 权限升级 —— PE1~PE5](#d-权限升级--pe1pe5)
- [E. 供应链 —— SC1~SC6](#e-供应链--sc1sc6)
- [F. 工具滥用 —— TM1~TM3](#f-工具滥用--tm1tm3)
- [G. SSRF —— SSRF1~SSRF3](#g-ssrf--ssrf1ssrf3)
- [H. 输出处理 —— OH1~OH3](#h-输出处理--oh1oh3)
- [I. 越权自我修改 —— RA1~RA2](#i-越权自我修改--ra1ra2)

---

## A. 动态代码执行 —— AST1~AST9

### AST1 · `exec()` 🟠 HIGH

直接调用 `exec()` 允许任意代码执行。**禁止**。
- 替代:如需动态执行,用受限沙箱、`ast.literal_eval` 或模板

### AST2 · `eval()` 🟠 HIGH

直接调用 `eval()`。**禁止**。
- 替代:数据解析用 `ast.literal_eval`;表达式求值用显式解析

### AST3 · `__import__()` 🟡 MEDIUM

动态 import。**禁止**用于变量模块名。
- 替代:静态 `import` 或 `importlib.import_module(白名单里的固定字符串)`

### AST4 · subprocess 危险调用 🟡 MEDIUM

以下函数**必须**用列表形式参数 + `shell=False`:
```
subprocess.call / run / Popen / check_output / check_call / getoutput / getstatusoutput
```

### AST5 · os exec 家族 🟠 HIGH

**禁止**所有下列调用:
```
os.system, os.popen,
os.execl, os.execle, os.execlp, os.execlpe, os.execv, os.execve, os.execvp, os.execvpe,
os.spawnl, os.spawnle, os.spawnlp, os.spawnlpe, os.spawnv, os.spawnve, os.spawnvp, os.spawnvpe,
os.posix_spawn, os.posix_spawnp
```
- 替代:统一用 `subprocess.run([...], shell=False)`

### AST6 · `compile()` 🟡 MEDIUM

从字符串构造代码对象。除非用户明确要求,否则**禁止**。

### AST7 · 动态 `getattr()` 🟢 LOW

`getattr(obj, 变量名)`(第二个参数非字面量)。
- 替代:显式属性访问、或字典白名单查找

### AST8 · 危险执行链 🔴 CRITICAL

**任何一种**都必须拒绝:
- `exec(base64.b64decode(...))`
- `eval(bytes.fromhex(...))`
- `exec(requests.get(url).text)`
- `exec(compile(base64.b64decode(...), ...))`
- `eval(await fetch(url))`
- `new Function(atob(...))`

### AST9 · 反射式 sink 🟠 HIGH

**禁止**用 `getattr` 拿以下**字面量**再调用:
```
exec, eval, system, popen, __import__
```
即 `getattr(os, "system")(cmd)` = 隐藏版 `os.system(cmd)`,直接拒绝。

---

## B. 数据流污点 —— TT1~TT5

### Sources(污点起点)

| 类别 | 具体函数 |
|---|---|
| 凭证/环境 | `os.environ`、`os.environ.get`、`os.getenv` |
| 文件读取 | `open`(读模式)、`pathlib.Path.read_text`、`pathlib.Path.read_bytes` |
| 网络输入 | `requests.get/post/put/patch/delete`、`httpx.*`、`urllib.request.urlopen`、`urllib.request.urlretrieve`、`socket.recv`、`socket.recvfrom` |
| 用户输入 | `input`、`sys.stdin.read`、`sys.stdin.readline` |

### Sinks(污点终点)

| 类别 | 具体函数 |
|---|---|
| 网络输出 | `requests.post/put/patch/get`、`httpx.*`、`urllib.request.urlopen`、`socket.send/sendall/sendto` |
| 代码执行 | `exec`、`eval`、`compile`、`os.system`、`os.popen`、`subprocess.run/call/check_output/check_call/Popen` |
| 文件写入 | `open`(w/a 模式)、`pathlib.Path.write_text/write_bytes`、`shutil.copy/copy2/copyfile` |

### 组合规则

| 规则 | 严重度 | 触发条件 |
|---|---|---|
| **TT3** | 🔴 CRITICAL | 凭证 source → 网络 sink(**凭证外传**) |
| **TT5** | 🔴 CRITICAL | 网络/用户输入 source → 代码执行 sink(**RCE**) |
| **TT4** | 🟠 HIGH | 文件读 source → 网络 sink(**文件外传**) |
| **TT1** | 🟠 HIGH | 任意 source 直接进 sink |
| **TT2** | 🟡 MEDIUM | source → 中间变量 → sink |

**AI 写代码时的自查规则**:任何时候你写完一段代码,过一遍上面的 source/sink 列表,如果发现两者之间没有验证/清洗/白名单,就是问题。

---

## C. 数据外传 —— E1~E5

### E1 · 外部 HTTP 传输 🟡 MEDIUM

常见触发点(**这些写法本身不禁,但要审慎**):
- `requests.post("https://...")` / `httpx.post/put(...)`
- `urllib.request.urlopen(..., data=...)`
- `fetch("https://...", {method: "POST"})`
- `curl -d / --data / --data-raw`
- `wget --post-data / --post-file`
- URL 中带 `api.` / `data.` / `collect.` / `telemetry.` / `analytics.`

### E2 · 环境变量收割 🟠 HIGH

**禁止**:
- `for k, v in os.environ.items(): ...`(**批量读环境变量**)
- `os.environ["*KEY*"]` / `os.environ.get("*_TOKEN*")` 等抓 KEY/SECRET/TOKEN/PASSWORD/CREDENTIAL 关键字的
- `os.environ.copy()`
- `Object.keys(process.env)`
- `env | grep -i (key|secret|token|password)`
- `printenv *KEY*`

### E3 · 文件系统枚举 🟡 MEDIUM

**禁止**:
- `glob.glob("*.env" / "*.ssh" / "*.aws" / "credentials")`
- `os.walk(home / ~ / /Users / /home)`
- `Path.home().glob(...)` / `Path.home().rglob(...)`
- `os.listdir("~/.ssh" / "~/.aws" / "~/.config" / "~/.gnupg")`
- `find ~ -name "*.env|*.pem|*.key|credential*"`
- `ls -laR ~/` / `ls -laR /home/`

### E4 · 会话上下文外泄 🟠 HIGH

**禁止**任何将 `conversation / chat / dialog / session / history / context / messages` 上传外部服务的代码或指令。

### E5 · 云存储外传 🟡 MEDIUM

**审慎**(合法备份也用这些 API,但要确认桶归属):
- boto3: `.put_object(...)`、`.upload_file(...)`、`.upload_fileobj(...)`
- AWS CLI: `aws s3 cp/sync/mv`、`aws s3api put-object`
- GCS: `.upload_from_filename/string/file(...)`、`gsutil cp/rsync/mv`
- Azure: `.upload_blob(...)`、`az storage blob upload`

---

## D. 权限升级 —— PE1~PE5

### PE1 · 过度权限声明 🟢 LOW

- `permissions: ["*"]` / `permissions: ["all"]`
- "grant/give full access"、"escalate/elevate my permissions"
- 声明多个 `shell_execute + file_write + network` 的组合

### PE2 · sudo / root 🟡 MEDIUM

- `sudo <cmd>`(排除 `sudo -v/-l/--version/--list`)
- `sudo -i` / `sudo -s` / `sudo -S` / `sudo -E`
- `sudo su` / `su root` / `su -`
- `doas`、`pkexec`
- `chmod u+s` / `chmod +s`(SUID)、`chmod 4755` / `chmod 6755`(SUID/SGID)
- "run as root"、"needs root access"

### PE3 · 凭证文件访问 🟠 HIGH

**禁止**读取以下路径:

| 类别 | 具体路径 |
|---|---|
| SSH | `~/.ssh/id_rsa`、`id_ed25519`、`id_ecdsa`、`id_dsa`、`authorized_keys`、`known_hosts` |
| AWS | `~/.aws/credentials`、`~/.aws/config` |
| GCP | `~/.config/gcloud/`、`application_default_credentials.json` |
| Azure | `~/.azure/`、`accessTokens.json` |
| Kubernetes | `~/.kube/config`、`kubeconfig` |
| Docker | `~/.docker/config.json` |
| npm | `~/.npmrc` |
| Git | `~/.git-credentials`、`~/.netrc` |
| 系统 | `/etc/passwd`(读取要警惕)、`/etc/shadow`(严格禁止) |
| 通用 | `password.*`、`credentials.*`、`secrets.*`、`.env(.local|.production|.development)` |
| Token | `access_token.txt`、`refresh_token.txt`、`bearer_token.txt`、`api_token.txt` |
| 系统钥匙串 | keychain / keyring / gnome-keyring / Chrome-Firefox-Safari 的 Cookies/Login Data/key4.db |

### PE4 · Docker socket 访问 🟠 HIGH

**禁止**:
- `/var/run/docker.sock`
- `docker.from_env()`
- `DockerClient(...)`
- `http+unix://.../docker.sock`

### PE5 · 特权容器 / 容器逃逸 🟠 HIGH

**禁止**:
- `--privileged`
- `-v /:...` / `--volume=/:...`(挂载宿主机根)
- `--cap-add=SYS_ADMIN / ALL / SYS_PTRACE / NET_ADMIN`
- `--pid=host` / `--net=host` / `--ipc=host` / `--uts=host`
- `--device=/dev/...`
- `--security-opt=...unconfined`
- `nsenter`、`unshare --user/--mount/--pid`
- 触碰 `/sys/fs/cgroup/*/release_agent`、`/proc/<pid>/ns/`

---

## E. 供应链 —— SC1~SC6

### SC1 · 未 pin 依赖 🟢 LOW

- `requirements.txt` 里裸包名(无版本)
- `pyproject.toml` 只写 `>=1.2` 没上界
- `package.json` 里 `"*"` 或 `"latest"`

### SC2 · 远程脚本执行 🟠 HIGH

**禁止**:
```
curl <url> | (sudo )?(ba)?sh
wget <url> | (sudo )?(ba)?sh
curl/wget <url> | python/python3/node/ruby/perl
curl <url> -o file && (sudo )?(ba)?sh file
exec(urllib/requests/httpx.<something>.read/text/content)
eval(await fetch(<url>))
new Function(fetch(<url>))
subprocess.<X>([..., "curl", "https://..."])
```

**豁免可信域名**:`deb.nodesource.com` / `rpm.nodesource.com` / `get.docker.com` / `install.python-poetry.org` / `raw.githubusercontent.com` / `brew.sh` / `rustup.rs` / `pypa.io` / `pip.pypa.io` / `astral.sh` / `pypi.org` / `npmjs.com` / `github.com`

### SC3 · 混淆代码 🟠 HIGH

**禁止**:
```
exec(base64.b64decode(...))
eval(base64.b64decode(...))
exec(codecs.decode(..., "hex"))
marshal.loads(...) / exec(marshal.loads(...))
exec(compile(..., base64...))
exec(bytes.fromhex(...))
exec(bytearray.fromhex(...))
exec(zlib.decompress(...) / gzip.decompress(...))
eval(atob(...))          // JS
new Function(atob(...))  // JS
__import__("os").system(...)
(lambda _: exec(...))(...)
_0x<hex>(...)  // 混淆器常见变量命名
```
连续 200+ 字符的 hex / base64 字面量也算可疑。

### SC4 · 已知漏洞依赖(部分快查)

以下版本**及以下**存在已知 CVE(实际扫描请查 [osv.dev](https://osv.dev)):

| Python 包 | 修复起点 | CVE |
|---|---|---|
| `pyyaml` | `>= 5.4` | CVE-2020-14343 (yaml.load 任意代码执行) |
| `urllib3` | `>= 1.26.5` | CVE-2021-33503 (ReDoS) |
| `pillow` | `>= 9.0.0` | CVE-2022-22817 (任意代码执行) |
| `certifi` | `>= 2022.12.07` | CVE-2023-37920 (信任根移除) |
| `requests` | `>= 2.31.0` | CVE-2023-32681 (redirect 泄露头) |
| `jinja2` | `>= 3.1.3` | CVE-2024-22195 (XSS) |
| `cryptography` | `>= 41.0.6` | CVE-2023-49083 |
| `django` | `>= 4.2.7` | CVE-2023-46695 (DoS) |
| `flask` | `>= 2.3.2` | CVE-2023-30861 (session cookie) |
| `aiohttp` | `>= 3.8.6` | CVE-2023-47627 (HTTP request smuggling) |
| `paramiko` | `>= 3.4.0` | CVE-2023-48795 (Terrapin SSH) |
| `py`(任意版本) | — | CVE-2022-42969 + 已不维护 |
| `pycrypto`(任意版本) | — | 停维护,用 `pycryptodome` |

npm 高危包(**直接告警,不要装**):
`event-stream`、`flatmap-stream`、`ua-parser-js < 0.7.31`、`coa < 2.0.2`、`rc < 1.2.8`、`node-ipc < 10.1.0`、`colors@1.4.0-4.1.x`(protestware)、`faker@5.5.4-6.6.6`(protestware)

### SC5 · 已弃用包(禁止新引入)

Python:`pycrypto`、`nose`、`optparse`、`distribute`、`request`(npm 的,别和 requests 混)以及 Python 2 遗留(`mimetools`、`popen2`、`rfc822`、`sets`、`sha`、`md5`、`commands`、`sgmllib`、`xmllib` 等)。

npm:`request`、`nomnom`、`optimist`、`dominion`、`npm-conf`。

### SC6 · Typosquatting(常见 popular 包名)

安装前对着这份"正牌名单"过一眼:

**Python 正牌**:`requests`、`numpy`、`pandas`、`flask`、`django`、`boto3`、`setuptools`、`pip`、`urllib3`、`pyyaml`、`cryptography`、`pillow`、`pydantic`、`sqlalchemy`、`pytest`、`click`、`jinja2`、`httpx`、`aiohttp`、`fastapi`、`celery`、`paramiko`、`beautifulsoup4`、`lxml`、`scrapy`、`redis`、`pymongo`、`psycopg2`、`matplotlib`、`scipy`、`scikit-learn`、`tensorflow`、`torch`、`keras`、`transformers`、`openai`、`langchain`、`gunicorn`、`uvicorn`、`rich`、`typer`、`black`、`ruff`、`mypy`、`pylint`、`flake8`、`isort`。

**npm 正牌**:`express`、`react`、`react-dom`、`next`、`vue`、`angular`、`lodash`、`axios`、`moment`、`chalk`、`commander`、`inquirer`、`webpack`、`babel`、`eslint`、`prettier`、`typescript`、`jest`、`mocha`、`chai`、`puppeteer`、`socket.io`、`mongoose`、`sequelize`、`passport`、`jsonwebtoken`、`dotenv`、`cors`、`body-parser`、`nodemon`、`pm2`。

**红灯规则**:待装包名和上面某个正牌**编辑距离 ≤ 2 且相对差异 < 1/3**(如 `reqeusts` vs `requests`)—— 停下来问用户是不是打错了。

---

## F. 工具滥用 —— TM1~TM3

### TM1 · 参数滥用 🟠 HIGH

**禁止**(除非用户明确说要):
- `subprocess.<x>(..., shell=True)` / `Popen(..., shell=True)`
- `rm/del/erase -r/-rf/-fr /` 或 `~`
- `--force delete/remove/push/reset/clean`
- `--no-verify / --no-check / --no-validate / --no-confirm / --no-protect / --no-safe`
- `--skip-validation / --skip-verification / --skip-checks / --skip-auth / --skip-tests`
- `--allow-empty / --allow-root / --allow-unrelated / --allow-unsafe`
- `shutil.rmtree("/")`
- `chmod 777` / `chmod 666` / `chmod a+rwx` / `chown` 递归改属主
- `git push --force`(尤其对主干)、`git reset --hard`、`git clean -fdx`
- `curl -k` / `curl --insecure` / `wget --no-check-certificate`
- `f"SELECT ... {var} ... DROP/DELETE/UPDATE/INSERT/ALTER/TRUNCATE"`(**SQL 注入**)

**豁免**:
- 标准 Docker 命令(`docker run --rm`、`docker build`、`podman run` 等)
- 标准 Dockerfile 清理(`rm -rf /var/lib/apt/lists/*`、`rm -rf /root/.cache`、`chown -R user:group /path`)

### TM2 · 链式绕过 🟠 HIGH

- `... && rm -` / `; rm -`
- `... && curl ... | bash`
- `... && sudo ...`
- `... && chmod 777` / `chmod -R`
- `| sudo ...`
- `| sh/bash/zsh/python/node/ruby/perl`(命令末尾)
- `| tee ... rm/del/sudo/curl`
- `| xargs ... rm/del/sudo/curl`

### TM3 · 不安全默认值 🟡 MEDIUM

**任何**关掉安全默认的代码都要标红:
- `verify=False`、`VERIFY_SSL=False`、`ssl_verify=False`、`tls_verify=False|off|no|0`
- `REQUESTS_CA_BUNDLE=""`、`CURL_CA_BUNDLE=""`
- `NODE_TLS_REJECT_UNAUTHORIZED=0`
- `auth=None|False|disabled|off`、`require_auth=False`
- `allow_anonymous=True`
- CORS `*`、`Access-Control-Allow-Origin: *`
- `mode=0o777` / `0o666`、"world-readable/writable/executable"
- 生产环境 `DEBUG=True` / `FLASK_ENV=development` / `NODE_ENV=development`
- `safe_mode=False` / `secure_mode=False` / `sandbox=False`
- "disable/skip/ignore/bypass security/auth/validation/sanitization/encoding/escaping"

---

## G. SSRF —— SSRF1~SSRF3

### SSRF1 · 云元数据 🟠 HIGH

**禁止**(除非用户是在写云运维工具且明确要求):
- `169.254.169.254`(AWS/GCP/Azure/OpenStack IMDS)
- `metadata.google.internal`
- `100.100.100.200`(阿里云)
- `fd00:ec2::254`(AWS IPv6 IMDS)

### SSRF2 · 内网请求 🟡 MEDIUM

`requests/httpx/aiohttp/urllib/session/fetch/axios/XMLHttpRequest/curl/wget` 访问:
- `localhost` / `127.0.0.1` / `0.0.0.0` / `[::1]`
- `10.x.x.x` / `192.168.x.x` / `172.16-31.x.x`

如是本地测试合法,但写进生产 skill 的默认 URL 一定要问用户。

### SSRF3 · 动态目标 🟡 MEDIUM

**禁止**用未验证外部输入拼 URL:
```python
requests.get(f"https://{user_input}/...")  # 危险
fetch(`https://${input}/...`)               # 危险
```
必须先把 host 过白名单再发。

---

## H. 输出处理 —— OH1~OH3

### OH1 · 未验证输出注入 🟠 HIGH

**禁止**把 LLM 返回值直接送进危险 sink,常见触发变量名:`response / output / result / answer / completion / reply / generated`。

具体不能这么写:
- `exec(response)` / `eval(output)`
- `subprocess.<x>(..., response)` / `os.system(output)` / `os.popen(result)`
- `element.innerHTML = response`(**XSS**)
- `document.write(output)`
- jQuery `.html(response)`
- React `dangerouslySetInnerHTML={{ __html: output }}`(未清洗)
- `cursor.execute(f"... {response}")`(**SQL 注入**)
- `f"SELECT/INSERT/UPDATE/DELETE ... {output}"`

**正确姿势**:LLM 输出**总是**要过 schema 验证 / 转义 / 参数化。

### OH2 · 跨上下文流转 🟡 MEDIUM

- 把 A agent 的输出直接当 B agent 的 system prompt
- 跨 session / 跨用户 / 跨租户共享上下文
- 把外部 LLM 输出直接注入本地 agent 的 prompt

### OH3 · 无边界输出 🟡 MEDIUM

**禁止**:
- `max_tokens=None / float("inf") / math.inf / 999999+`
- `max_length=None / 0 / -1`
- "generate unlimited / unbounded / infinite text"
- "repeat/loop indefinitely / forever / continuously"
- "keep generating until stopped/killed/interrupted"
- "flood/spam/fill the output/log/console"

---

## I. 越权自我修改 —— RA1~RA2

### RA1 · 自我修改 🟠 HIGH

**禁止**:
- `open(__file__, "w")` / `Path(__file__).write_text(...)`
- 打开并写 `SKILL.md` / `skill.md`
- "modify/edit/rewrite your own code / this skill's config / the current file"
- "self-modify / self-update / self-rewrite / self-patch / self-evolve"
- "append/inject code into this file/skill"
- "disable/remove/bypass the safety/security/guard/protection/constraint"
- "comment out the validation/verification/check/guard/assertion"

### RA2 · 会话持久化 🟡 MEDIUM

**除非用户明确要求**,禁止:
- `crontab -e` / `crontab -l` / 写入 crontab
- "add a cron job / recurring task / periodic script"
- 追加到 `~/.bashrc` / `~/.zshrc` / `~/.profile` / `~/.bash_profile` / `~/.login` / `~/.cshrc`
- "install as startup/boot/autostart/login script"
- `systemd enable/install`、`launchctl load`、`init.d`
- 创建 `.<name>` 隐藏文件在 `~/` 或 `/tmp/` 用作持久状态
- `nohup ... &` / `disown` / `setsid`(启动后台常驻)
- Windows: `HKEY_*` / `reg add` / `RegSetValue`
- macOS: `defaults write`、`plist`、`launchctl load`

---

## 使用方式

1. **平常时**:遵守 [SKILL.md](SKILL.md) 的红线即可,不需要每次查这份文档
2. **拿不准时**:AI 读这份文档的对应章节,对着表格比对
3. **写扫描器时**:每条规则背后都有 SkillSpector 的正则/AST 实现,可以直接照抄

## 出处

规则源码位于 SkillSpector 项目 `src/skillspector/nodes/analyzers/`:

| 本文件章节 | 对应源文件 |
|---|---|
| A. AST | `behavioral_ast.py` |
| B. 污点 | `behavioral_taint_tracking.py` |
| C. 外传 | `static_patterns_data_exfiltration.py` |
| D. 权限 | `static_patterns_privilege_escalation.py` |
| E. 供应链 | `static_patterns_supply_chain.py` |
| F. 工具滥用 | `static_patterns_tool_misuse.py` |
| G. SSRF | `static_patterns_ssrf.py` |
| H. 输出 | `static_patterns_output_handling.py` |
| I. 自改 | `static_patterns_rogue_agent.py` |
