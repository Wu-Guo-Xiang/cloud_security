# merge_settings_env.ps1
# Plugin 版 install 的合并脚本
#   - merge env (LLM URL/Token) — 直接从参数写入,不经过中间文件
#   - 清空 hooks — plugin 化后 hooks 由 plugin/hooks/hooks.json 接管,
#     旧 settings.json 里如果还有指向 C:\ProgramData\ClaudeSecurity\ 的
#     hook 会和 plugin hook 双跑,规则冲突时导致 tool call 静默中断。
#     不清空 -> 中断;清空 -> 老 scanner 停跑,plugin 独占。
#     如果检测到 hooks 段非空,原样备份到 settings.json.hooks_bak_YYYYMMDD_HHMMSS.json
#   - merge permissions.deny — 禁止 Claude Code 执行删除/外发等危险命令
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File merge_settings_env.ps1 `
#       -LlmUrl    "http://192.168.3.124:4000"  `
#       -LlmToken  "sk-xxxxxxxx"                `
#       -Settings  "C:\Users\alice\.claude\settings.json"

param(
    [Parameter(Mandatory=$true)] [string] $Settings,
    [string] $LlmUrl = "",
    [string] $LlmToken = "",
    [string] $LlmModel = "",
    [string] $PyExe = ""
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) { Write-Host "[merge-env] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[merge-env] $msg" -ForegroundColor Yellow }
function Write-Err($msg)  { Write-Host "[merge-env] $msg" -ForegroundColor Red }

try {
    $settingsDir = Split-Path -Parent $Settings
    if (!(Test-Path $settingsDir)) {
        New-Item -ItemType Directory -Force -Path $settingsDir | Out-Null
    }

    $current = [ordered]@{}
    if (Test-Path $Settings) {
        $ts  = Get-Date -Format "yyyyMMdd_HHmmss"
        $bak = "$Settings.bak_$ts"
        Copy-Item $Settings $bak -Force
        Write-Info "backup: $bak"

        $raw = Get-Content $Settings -Raw -Encoding UTF8
        if ($raw -and $raw.Trim()) {
            $parsed = $raw | ConvertFrom-Json
            $parsed.PSObject.Properties | ForEach-Object {
                $current[$_.Name] = $_.Value
            }
        }
    }

    # ---------- 1. merge env (LLM URL/Token, preserve existing keys) ----------
    # Only copy existing env entries when they come from ConvertFrom-Json (PSCustomObject).
    # An OrderedDictionary's .PSObject.Properties returns .NET type members (Count,
    # IsReadOnly, Keys, ...) instead of dictionary entries, which would pollute the
    # env section and corrupt the Keys property. So we skip copying in that case.
    $envAcc = [ordered]@{}
    if ($current.Contains("env") -and $current["env"] -is [System.Management.Automation.PSCustomObject]) {
        $current["env"].PSObject.Properties | ForEach-Object {
            $envAcc[$_.Name] = $_.Value
        }
    }
    if ($LlmUrl) {
        $envAcc["ANTHROPIC_BASE_URL"] = $LlmUrl
        Write-Info "env.ANTHROPIC_BASE_URL set"
    } else {
        Write-Info "env.ANTHROPIC_BASE_URL skipped (empty LlmUrl, keeping existing)"
    }
    if ($LlmToken) {
        $envAcc["ANTHROPIC_AUTH_TOKEN"] = $LlmToken
        Write-Info "env.ANTHROPIC_AUTH_TOKEN set"
    } else {
        Write-Info "env.ANTHROPIC_AUTH_TOKEN skipped (empty LlmToken, keeping existing)"
    }

    if ($LlmModel) {
        $envAcc["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = $LlmModel
        $envAcc["ANTHROPIC_DEFAULT_HAIKU_MODEL_NAME"] = $LlmModel
        $envAcc["ANTHROPIC_DEFAULT_OPUS_MODEL"] = $LlmModel
        $envAcc["ANTHROPIC_DEFAULT_OPUS_MODEL_NAME"] = $LlmModel
        $envAcc["ANTHROPIC_DEFAULT_SONNET_MODEL"] = $LlmModel
        $envAcc["ANTHROPIC_DEFAULT_SONNET_MODEL_NAME"] = $LlmModel
        Write-Info "env.ANTHROPIC_DEFAULT_*_MODEL set to $LlmModel"
    } else {
        Write-Info "env.ANTHROPIC_DEFAULT_*_MODEL skipped (empty LlmModel, keeping existing)"
    }

    # CLOUD_GUARD_PYTHON — 写入 settings.json env，让 Claude Code 进程(及其 hook
    # 子进程)直接拿到 bundled Python 路径，不依赖 setx + 注销/重登。
    # 否则 input_scanner.cmd 在员工机(无系统 Python)上回退 py -3 失败，hook 静默
    # 不写日志 —— 表现为"装完只有冒烟测试那 2 条日志，之后问答不记录"。
    if ($PyExe) {
        $envAcc["CLOUD_GUARD_PYTHON"] = $PyExe
        Write-Info "env.CLOUD_GUARD_PYTHON set = $PyExe (hooks 无需注销即可找到 Python)"
    } else {
        Write-Info "env.CLOUD_GUARD_PYTHON skipped (empty PyExe; 仍靠 setx + 注销/重登)"
    }

    $current["env"] = $envAcc

    # ---------- 2. clear hooks (plugin owns them now) ----------
    if ($current.Contains("hooks")) {
        $existingHooks = $current["hooks"]
        # count top-level event names (PreToolUse / PostToolUse / Stop / UserPromptSubmit ...)
        $eventCount = 0
        if ($existingHooks -is [System.Collections.IDictionary]) {
            $eventCount = $existingHooks.Keys.Count
        } elseif ($existingHooks -and $existingHooks.PSObject) {
            $eventCount = ($existingHooks.PSObject.Properties | Measure-Object).Count
        }

        if ($eventCount -gt 0) {
            # dump the removed hooks to a sidecar file so it can be restored
            $hookBakTs  = Get-Date -Format "yyyyMMdd_HHmmss"
            $hookBak    = "$Settings.hooks_bak_$hookBakTs.json"
            $existingHooks | ConvertTo-Json -Depth 32 | Set-Content -Path $hookBak -Encoding UTF8
            Write-Warn "cleared $eventCount existing hook event(s); backup: $hookBak"
            Write-Warn "  (plugin/hooks/hooks.json will handle hooks from now on)"
        } else {
            Write-Info "hooks key already empty, nothing to clear"
        }
    }
    $current["hooks"] = [ordered]@{}

    # ---------- 3. merge permissions (security policy: deny dangerous commands) ----------
    $permissionsObj = [ordered]@{
        deny = @(
            # --- 删除操作: Claude Code 不允许删除任何文件 ---
            "Bash(rm:*)",
            "Bash(del:*)",
            "Bash(rmdir:*)",
            "Bash(rd:*)",
            "Bash(Remove-Item:*)",
            "Bash(shred:*)",
            "Bash(truncate:*)",
            "Bash(git clean:*)",
            "Bash(git reset --hard:*)",
            "Bash(git rm:*)",
            "Bash(npm uninstall:*)",
            "Bash(pip uninstall:*)",
            "Bash(docker rmi:*)",
            "Bash(docker rm:*)",
            "Bash(docker volume rm:*)",
            "Bash(docker network rm:*)",
            "Bash(kubectl delete:*)",
            # --- 外发/网络: 禁止数据外传 ---
            "Bash(curl **)",
            "Bash(wget **)",
            "Bash(nc **)",
            "Bash(scp **)",
            "Bash(rsync **)",
            "Bash(ssh **)",
            "Bash(sftp **)",
            # --- 环境变量泄露 ---
            "Bash(env)",
            "Bash(printenv)",
            "Bash(set)",
            # --- 编码绕过 ---
            "Bash(xxd **)",
            "Bash(base64 **)",
            # --- 文件系统格式化 ---
            "Bash(format:*)",
            "Bash(mkfs:*)",
            "Bash(diskpart:*)"
        )
    }
    if ($current.Contains("permissions")) {
        $existingPerms = $current["permissions"]
        if ($existingPerms -and $existingPerms.PSObject.Properties["deny"]) {
            $existingDeny = $existingPerms.deny
            if ($existingDeny -is [System.Array]) {
                $mergedDeny = [System.Collections.Generic.List[string]]::new()
                foreach ($d in $existingDeny) { $mergedDeny.Add($d) }
                foreach ($d in $permissionsObj.deny) {
                    if (-not $mergedDeny.Contains($d)) { $mergedDeny.Add($d) }
                }
                $permissionsObj.deny = $mergedDeny.ToArray()
                Write-Info "permissions.deny merged (added missing entries)"
            }
        }
    }
    $current["permissions"] = $permissionsObj
    Write-Info "permissions.deny set"

    # ---------- 4. write back (pretty-print, UTF8 without BOM) ----------
    $json = $current | ConvertTo-Json -Depth 32
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Settings, $json, $utf8NoBom)

    Write-Info "OK  -> $Settings"
    exit 0

} catch {
    Write-Err "merge failed: $($_.Exception.Message)"
    exit 1
}
