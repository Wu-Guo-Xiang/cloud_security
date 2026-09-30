"""飞书组织架构同步工具 — 从飞书拉取部门树 + 员工真实姓名, 导出 CSV。

被 claude_audit.plugin_status.sync_org_from_feishu() 作为子进程调用,
默认输出到 claude_audit/api/data/org_structure.csv。

凭证优先从环境变量 FEISHU_APP_ID / FEISHU_APP_SECRET 读取, 未设则用下方默认值。

依赖: lark_oapi, requests (已在 requirements.txt 中)。
"""
import io
import os
import sys

import lark_oapi as lark
from lark_oapi.api.contact.v3 import (
    ListDepartmentRequestBuilder,
    ListUserRequestBuilder,
)
import requests

# Windows 控制台 UTF-8 输出
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ================= 配置区域 =================
# 凭证优先用环境变量, 方便服务器部署时不改代码; 默认值为现有应用
APP_ID = os.environ.get("FEISHU_APP_ID", "cli_your_feishu_app_id_placeholder")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET", "your_feishu_app_secret_placeholder")

client = lark.Client.builder() \
    .app_id(APP_ID) \
    .app_secret(APP_SECRET) \
    .log_level(lark.LogLevel.WARNING) \
    .build()


# ================= token 获取 =================
_token_cache = {"token": "", "ts": 0}


def _get_tenant_token() -> str:
    """获取 tenant_access_token（自动缓存，2小时有效期内复用）。"""
    import time
    now = time.time()
    if _token_cache["token"] and now - _token_cache["ts"] < 6000:
        return _token_cache["token"]
    resp = requests.post(
        "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal",
        json={"app_id": APP_ID, "app_secret": APP_SECRET},
        timeout=15,
    )
    token = resp.json().get("tenant_access_token", "")
    _token_cache["token"] = token
    _token_cache["ts"] = now
    return token


# ================= directory API 查姓名 =================
# 飞书限流常见返回码(触发时应退避重试而非直接失败)
_RATE_LIMIT_CODES = (429, 99991400, 99991401)


def _fetch_one_name(open_id: str, token: str) -> str:
    """directory API 单人查询: 传入 open_id 返回中文姓名。

    注意: directory API 的 mget 在批次中混入无效 id 会导致整批返回空,
    且返回的 employee_id 字段不可信(与传入 open_id 不符),
    所以必须单人查询, 单人返回即对应传入者。

    带限流退避重试: 飞书对高频并发请求会限流, 触发时退避重试最多 4 次。
    """
    import time as _time

    url = "https://open.feishu.cn/open-apis/directory/v1/employees/mget?employee_id_type=open_id"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    body = {"employee_ids": [open_id], "required_fields": ["base_info.name", "base_info.email"]}

    last_err = ""
    for attempt in range(4):
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=30)
            if resp.status_code == 429:
                last_err = "HTTP 429 限流"
                _time.sleep(1.5 * (attempt + 1))
                continue
            data = resp.json()
            code = data.get("code")
            if code in _RATE_LIMIT_CODES:
                last_err = f"限流 code={code}"
                _time.sleep(1.5 * (attempt + 1))
                continue
            if code != 0:
                return ""  # 该账号查不到(非限流错误), 不重试
            emps = data.get("data", {}).get("employees", []) or []
            if not emps:
                return ""
            name_obj = emps[0].get("base_info", {}).get("name", {}).get("name", {})
            return name_obj.get("default_value", "") or name_obj.get("i18n_value", {}).get("zh_cn", "")
        except Exception as e:
            last_err = str(e)
            _time.sleep(1.0 * (attempt + 1))
    return ""


def fetch_names_by_directory_api(open_ids: list[str]) -> dict[str, str]:
    """用 directory/v1/employees/mget 并发单人查员工真实姓名。

    contact API 的 base:readonly 权限拿不到 name,
    但 directory API 能返回 name.default_value(中文姓名)。
    directory API 批量查询有"一个坏 id 连累整批"的问题, 故单人查询 + 线程池并发。
    并发降到 8 以避免触发飞书限流(之前 20 线程会大量 429 导致查不全)。

    返回: {open_id: "吴国响", ...}
    """
    if not open_ids:
        return {}

    from concurrent.futures import ThreadPoolExecutor, as_completed

    token = _get_tenant_token()
    result: dict[str, str] = {}

    def _task(oid: str) -> tuple[str, str]:
        return oid, _fetch_one_name(oid, token)

    # 低并发(8 线程) + 每请求内置限流重试, 稳定但稍慢(603 人约 2-4 分钟)
    failed = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_task, oid): oid for oid in open_ids}
        done = 0
        for fut in as_completed(futures):
            oid, name = fut.result()
            if name:
                result[oid] = name
            else:
                failed += 1
            done += 1
            if done % 100 == 0:
                print(f"  ...已查 {done}/{len(open_ids)}, 成功 {len(result)}, 失败 {failed}")

    if failed:
        print(f"  [提示] {failed} 人未查到姓名(可能是限流重试后仍失败/无权限账号)",
              file=sys.stderr)
    return result


def fetch_dept_names_by_batch_api(dept_ids: list[str]) -> dict[str, str]:
    """用 contact/v3/departments/batch 批量查部门名称。

    department.list 接口在 base:readonly 下不返回 name，
    但 batch 接口可以返回。

    返回: {open_department_id: "经理室", ...}
    """
    if not dept_ids:
        return {}

    result: dict[str, str] = {}
    token = _get_tenant_token()
    headers = {"Authorization": f"Bearer {token}"}
    batch_size = 50

    for i in range(0, len(dept_ids), batch_size):
        batch = dept_ids[i:i + batch_size]
        try:
            # departments/batch 是 GET 接口，department_ids 用重复参数名
            params = [
                ("department_id_type", "open_department_id"),
                ("user_id_type", "open_id"),
            ]
            for did in batch:
                params.append(("department_ids", did))

            resp = requests.get(
                "https://open.feishu.cn/open-apis/contact/v3/departments/batch",
                headers=headers,
                params=params,
                timeout=30,
            )
            data = resp.json()
            if data.get("code") != 0:
                print(f"  [警告] departments/batch 批次 {i // batch_size + 1} 失败: {data.get('msg', '')}",
                      file=sys.stderr)
                continue
            for dept in data.get("data", {}).get("items", []):
                dept_id = dept.get("open_department_id", "")
                name = dept.get("name", "")
                if dept_id and name:
                    result[dept_id] = name
        except Exception as e:
            print(f"  [警告] departments/batch 批次异常: {e}", file=sys.stderr)

    return result


# ================= 工具函数 =================
def _email_prefix(email: str) -> str:
    """邮箱前缀作为 fallback 显示名。"""
    if "@" in email:
        return email.split("@")[0]
    return ""


def _dept_display_name(dept) -> str:
    """部门显示名：优先 name，其次 open_department_id 缩写。"""
    name = dept.name
    if name:
        return name
    did = dept.open_department_id or ""
    if did:
        return did[:6] + "..." + did[-6:]
    return "(根部门)"


# ================= 获取组织架构（返回结构化数据） =================
def collect_org_data():
    """递归获取完整组织架构，返回 (dept_list, user_list)。

    dept_list: [{"id", "name", "parent_id", "member_count", "path"}, ...]
    user_list: [{"open_id", "email", "dept_id", "dept_path", "dept_name"}, ...]
    """
    print("正在获取组织架构（部门 + 员工）...")

    dept_list = []
    user_list = []

    def fetch(parent_id, parent_path=""):
        page_token = None
        while True:
            builder = ListDepartmentRequestBuilder() \
                .parent_department_id(parent_id) \
                .department_id_type("open_department_id") \
                .page_size(50)
            if page_token:
                builder = builder.page_token(page_token)
            resp = client.contact.v3.department.list(builder.build())
            if not resp.success():
                break
            for d in (resp.data.items or []):
                dept_id = d.open_department_id
                dept_name = d.name or _dept_display_name(d)
                dept_path = f"{parent_path}/{dept_name}" if parent_path else dept_name
                dept_list.append({
                    "id": dept_id,
                    "name": dept_name,
                    "parent_id": d.parent_department_id or "",
                    "member_count": d.member_count or 0,
                    "path": dept_path,
                })

                # 获取该部门下的员工
                users = _fetch_users(dept_id)
                for u in users:
                    user_list.append({
                        "open_id": u.open_id or "",
                        "email": u.email or u.enterprise_email or "",
                        "dept_id": dept_id,
                        "dept_path": dept_path,
                        "dept_name": dept_name,
                    })

                fetch(dept_id, dept_path)
            if not resp.data.has_more:
                break
            page_token = resp.data.page_token

    fetch("0")
    print(f"  部门 {len(dept_list)} 个，员工 {len(user_list)} 人")
    return dept_list, user_list


def _fetch_users(dept_id: str) -> list:
    """获取某部门下的直属员工列表"""
    users = []
    page_token = None
    while True:
        builder = ListUserRequestBuilder() \
            .department_id(dept_id) \
            .department_id_type("open_department_id") \
            .user_id_type("open_id") \
            .page_size(50)
        if page_token:
            builder = builder.page_token(page_token)
        resp = client.contact.v3.user.list(builder.build())
        if not resp.success():
            break
        users.extend(resp.data.items or [])
        if not resp.data.has_more:
            break
        page_token = resp.data.page_token
    return users


def enrich_user_names(user_list: list[dict]) -> None:
    """用 directory API 给 user_list 批量补充真实姓名（就地修改）。

    通过 open_id 列表查 directory API，返回的 open_id->name 映射回填。
    单人查询不依赖邮箱, 无邮箱者也能匹配到姓名。
    """
    # 收集所有有 open_id 的用户
    open_ids = [u["open_id"] for u in user_list if u["open_id"]]
    if not open_ids:
        return

    print(f"正在通过 directory API 并发查 {len(open_ids)} 人姓名...")
    # directory API 返回 open_id->name
    id_to_name = fetch_names_by_directory_api(open_ids)

    # 回填姓名
    matched = 0
    missing: list[dict] = []
    for u in user_list:
        oid = u.get("open_id", "")
        nm = id_to_name.get(oid, "") if oid else ""
        if nm:
            u["name"] = nm
            matched += 1
        else:
            u["name"] = ""
            missing.append(u)
    print(f"  匹配到 {matched}/{len(user_list)} 人姓名")
    if missing:
        print(f"  [提示] {len(missing)} 人未查到姓名(可能为未激活/离职/无权限账号):",
              file=sys.stderr)
        for u in missing:
            print(f"    - open_id={u.get('open_id','')} 部门={u.get('dept_path','')}",
                  file=sys.stderr)


def enrich_dept_names(dept_list: list[dict]) -> None:
    """用 departments/batch API 给 dept_list 批量补充真实部门名（就地修改）。

    list 接口在 base:readonly 下不返回 name，batch 接口可以。
    拿到真实名称后，同步更新 dept_path（重建路径，用真实部门名拼接）。
    """
    dept_ids = [d["id"] for d in dept_list if d["id"]]
    if not dept_ids:
        return

    print(f"正在通过 departments/batch API 批量查 {len(dept_ids)} 个部门名...")
    id_to_name = fetch_dept_names_by_batch_api(dept_ids)

    # 回填部门名
    matched = 0
    for d in dept_list:
        if d["id"] in id_to_name:
            d["name"] = id_to_name[d["id"]]
            matched += 1
    print(f"  匹配到 {matched}/{len(dept_list)} 个部门名")

    # 重建 dept_path（用真实部门名）
    id_map = {d["id"]: d["name"] for d in dept_list}
    parent_map = {d["id"]: d["parent_id"] for d in dept_list}

    def build_path(dept_id: str) -> str:
        """从当前部门往上追溯到根，拼接路径。"""
        parts = []
        cur = dept_id
        seen = set()
        while cur and cur != "0" and cur not in seen:
            seen.add(cur)
            name = id_map.get(cur, cur[:6] + "...")
            parts.append(name)
            cur = parent_map.get(cur, "")
        parts.reverse()
        return "/".join(parts)

    for d in dept_list:
        d["path"] = build_path(d["id"])


# ================= 输出 =================
def print_org_tree(dept_list: list[dict], user_list: list[dict]):
    """按树形结构打印组织架构。"""
    print("\n=== 组织架构 ===\n")

    from collections import defaultdict
    dept_users = defaultdict(list)
    for u in user_list:
        dept_users[u["dept_id"]].append(u)

    for d in sorted(dept_list, key=lambda x: x["path"]):
        depth = d["path"].count("/")
        indent = "  " * depth
        dept_name = d["name"]
        users = dept_users.get(d["id"], [])
        count_info = f"(成员:{d['member_count']}, 直属:{len(users)})"
        print(f"{indent}├─ 📂 {dept_name} {count_info}")
        for u in users:
            name = u.get("name") or _email_prefix(u["email"]) or u["open_id"][:12]
            email = u["email"]
            print(f"{indent}│   ├─ 👤 {name}  📧{email}")


def export_csv(dept_list: list[dict], user_list: list[dict], path: str):
    """导出 CSV：部门路径, 部门ID, 员工姓名, 邮箱, open_id。"""
    import csv
    print(f"正在导出 CSV 到 {path}...")

    rows = []
    users_by_dept = {}
    for u in user_list:
        users_by_dept.setdefault(u["dept_id"], []).append(u)

    for d in dept_list:
        users = users_by_dept.get(d["id"], [])
        if users:
            for u in users:
                rows.append({
                    "dept_path": d["path"],
                    "dept_name": d["name"],
                    "dept_id": d["id"],
                    "parent_dept_id": d["parent_id"],
                    "user_name": u.get("name", ""),
                    "user_email": u["email"],
                    "user_display": u.get("name") or _email_prefix(u["email"]) or "",
                    "open_id": u["open_id"],
                })
        else:
            rows.append({
                "dept_path": d["path"],
                "dept_name": d["name"],
                "dept_id": d["id"],
                "parent_dept_id": d["parent_id"],
                "user_name": "",
                "user_email": "",
                "user_display": "",
                "open_id": "",
            })
    out_dir = os.path.dirname(os.path.abspath(path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "dept_path", "dept_name", "dept_id", "parent_dept_id",
            "user_name", "user_email", "user_display", "open_id",
        ])
        writer.writeheader()
        writer.writerows(rows)

    print(f"  已导出 {len(rows)} 行到 {path}")


# ================= 主程序入口 =================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="飞书组织架构同步工具（含真实姓名）")
    parser.add_argument("--csv", default=None, help="导出 CSV 文件路径（如: org.csv）")
    parser.add_argument("--no-names", action="store_true", help="跳过 directory API 查姓名（仅用邮箱前缀）")
    args = parser.parse_args()

    # 1. 获取组织架构
    dept_list, user_list = collect_org_data()

    # 2. 补充部门真实名称（departments/batch API）
    enrich_dept_names(dept_list)

    # 3. 用 directory API 批量查真实姓名
    if not args.no_names:
        enrich_user_names(user_list)
    else:
        for u in user_list:
            u["name"] = ""

    # 3.5 数据完整性保护: 姓名匹配率过低说明飞书限流/网络异常导致拉取不全,
    #     此时拒绝导出(返回非零), 避免用不完整数据覆盖已有的完整 CSV。
    named = sum(1 for u in user_list if u.get("name"))
    if user_list and named < len(user_list) * 0.5:
        msg = (f"[中止] 姓名匹配率过低: {named}/{len(user_list)} (< 50%), "
               f"疑似飞书限流/网络异常, 已中止导出以免覆盖完整数据")
        print(msg, file=sys.stderr)
        sys.exit(1)

    # 同步更新 user_list 里的 dept_name / dept_path（用真实部门名）
    dept_map = {d["id"]: d for d in dept_list}
    for u in user_list:
        d = dept_map.get(u["dept_id"])
        if d:
            u["dept_name"] = d["name"]
            u["dept_path"] = d["path"]

    # 4. 输出
    if args.csv:
        export_csv(dept_list, user_list, args.csv)
    else:
        print_org_tree(dept_list, user_list)