import html
import json
import logging
import os
import re
import sys
import time
import base64
from bs4 import BeautifulSoup
from curl_cffi import requests

# 为了加密 GitHub Secret
try:
    from nacl import encoding, public
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================
# 可调参数（修复版新增）
# ============================================================
IMPERSONATE = "chrome131"            # FIX#9: chrome110 是 2023 年指纹，过旧；可改 chrome124~chrome150
TZ_OFFSET_SECONDS = 8 * 3600         # FIX#10: 通知时间按北京时间 UTC+8 显示
HTTP_TIMEOUT = 20
# FIX#5: Cloudflare 一次性 Cookie 绑定 IP+UA，跨 IP（如 GitHub Actions）无用甚至有害，解析时丢弃
CF_COOKIE_NAMES = {"cf_clearance", "__cf_bm", "_cfuvid", "cf_chl_2", "cf_chl_rc_ni"}
# FIX#1: Cloudflare 挑战页特征，用于把「CF 拦截」与「Cookie 失效」区分开
CF_MARKERS = (
    "just a moment", "cf-browser-verification", "attention required",
    "cf-challenge", "checking your browser", "enable javascript and cookies",
)
# FIX#7: 未支付/已支付行特征（已删除原关键词 "Invoice"——已支付行也含该词，会误伤）
# 注意用 \b 词边界：\bpaid\b 不会误匹配 "unpaid"
UNPAID_RE = re.compile(r'\bunpaid\b|待支付|未支付|待付款|overdue|逾期', re.IGNORECASE)
PAID_RE = re.compile(r'\bpaid\b|已支付|已付款|已付清', re.IGNORECASE)


def split_accounts(env_cookies):
    """FIX(T5): 多账号分割。
    优先按行分割；仅当单行内出现多个 hidencloud_session= 时才按 & 细分，
    避免 cookie 值中混入 & 时把单个账号切坏。"""
    accounts = []
    for line in env_cookies.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.count("hidencloud_session=") > 1:
            for part in line.split("&"):
                part = part.strip()
                if part:
                    accounts.append(part)
        else:
            accounts.append(line)
    return accounts


class HidenCloud:
    def __init__(self, cookie_str, tg_config=None):
        self.base_url = "https://dash.hidencloud.com"
        self.cookie_str = cookie_str
        self.tg_config = tg_config
        self.session = requests.Session(impersonate=IMPERSONATE)
        self.username = "Unknown"
        self.balance = "未知"
        self.updated_cookies = False
        self.csrf_token = ""
        self.fail_reason = ""          # 修复版新增：精确的失败原因
        self.task_failed = False       # 修复版新增：供 main() 决定退出码
        self.dashboard_html = None     # 修复版新增：复用首次请求，避免重复 GET
        self.parse_and_set_cookies()

    # ----------------------------------------------------------
    # Cookie 解析 / 序列化
    # ----------------------------------------------------------
    def _clean_cookie_item(self, item):
        """FIX#4: 清洗单个 cookie 片段。
        顺序很重要：必须先去 cookie: 前缀，再去引号，
        否则 `cookie: "k=v"` 去引号时引号不在首尾，残留前引号。"""
        item = item.strip()
        if item.lower().startswith('cookie:'):
            item = item[len('cookie:'):]
        return item.strip().strip('"').strip()

    def parse_and_set_cookies(self):
        """解析 Cookie 字符串并设置到 Session"""
        if not self.cookie_str:
            return

        cookies = {}
        dropped = []
        for raw_item in self.cookie_str.split(';'):
            item = self._clean_cookie_item(raw_item)
            if '=' not in item:
                continue
            key, value = item.split('=', 1)
            key = key.strip().strip('"')
            value = value.strip().strip('"')
            if not key or not value:
                continue
            if key in CF_COOKIE_NAMES:  # FIX#5: 丢弃 CF 一次性 cookie
                dropped.append(key)
                continue
            cookies[key] = value

        if dropped:
            logger.info(f"已丢弃 Cloudflare 一次性 Cookie（跨 IP 无效）: {', '.join(sorted(set(dropped)))}")
        # 只记录 cookie 名称，不记录值，避免密钥进入日志
        logger.info(f"已加载 {len(cookies)} 个应用 Cookie: {', '.join(sorted(cookies)) if cookies else '(无)'}")
        self.session.cookies.update(cookies)

    def _normalize_cookie_string(self, s):
        """FIX#6: 规范化 cookie 串（清洗 + 去 CF cookie + 按名排序），用于稳定比较"""
        d = {}
        for raw_item in s.split(';'):
            item = self._clean_cookie_item(raw_item)
            if '=' not in item:
                continue
            key, value = item.split('=', 1)
            key = key.strip().strip('"')
            value = value.strip().strip('"')
            if key and value and key not in CF_COOKIE_NAMES:
                d[key] = value
        return "; ".join(f"{k}={d[k]}" for k in sorted(d))

    def get_cookie_string(self):
        """FIX#6: 序列化当前 session 中的非 CF cookie，按名称排序保证输出稳定"""
        items = [(name, value) for name, value in self.session.cookies.items()
                 if name not in CF_COOKIE_NAMES]
        items.sort(key=lambda kv: kv[0])
        return "; ".join(f"{name}={value}" for name, value in items)

    # ----------------------------------------------------------
    # GitHub Secret 自动更新
    # ----------------------------------------------------------
    def update_github_secret(self, new_cookie):
        """自动更新 GitHub Secret"""
        gh_pat = os.environ.get("GH_PAT")
        repo = os.environ.get("GITHUB_REPOSITORY")
        secret_name = "HIDEN_COOKIE"

        if not gh_pat or not repo:
            logger.warning("未找到 GH_PAT 或 GITHUB_REPOSITORY，跳过 Secret 更新")
            return

        if not HAS_NACL:
            logger.error("未安装 pynacl 库，无法加密并更新 Secret")
            return

        logger.info(f"正在尝试更新 GitHub Secret: {secret_name}")
        headers = {
            "Authorization": f"token {gh_pat}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "HidenCloud-Renew-Bot"
        }

        try:
            # 1. 获取公钥
            pub_key_resp = requests.get(
                f"https://api.github.com/repos/{repo}/actions/secrets/public-key",
                headers=headers
            )
            if pub_key_resp.status_code != 200:
                logger.error(f"获取公钥失败: {pub_key_resp.text}")
                return

            pub_key_data = pub_key_resp.json()
            public_key = pub_key_data['key']
            key_id = pub_key_data['key_id']

            # 2. 加密 Secret
            def encrypt(public_key: str, secret_value: str) -> str:
                public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
                sealed_box = public.SealedBox(public_key)
                encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
                return base64.b64encode(encrypted).decode("utf-8")

            encrypted_value = encrypt(public_key, new_cookie)

            # 3. 提交更新
            put_resp = requests.put(
                f"https://api.github.com/repos/{repo}/actions/secrets/{secret_name}",
                headers=headers,
                json={
                    "encrypted_value": encrypted_value,
                    "key_id": key_id
                }
            )
            if put_resp.status_code in [201, 204]:
                logger.info(f"✅ GitHub Secret {secret_name} 更新成功！")
            else:
                logger.error(f"❌ 更新 Secret 失败: {put_resp.text}")

        except Exception as e:
            logger.error(f"更新 Secret 过程出错: {e}")

    # ----------------------------------------------------------
    # Telegram 通知
    # ----------------------------------------------------------
    def get_hitokoto(self):
        """获取每日一言"""
        try:
            resp = requests.get("https://v1.hitokoto.cn/?encode=json", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return f"『{data['hitokoto']}』—— {data['from']}"
        except Exception:
            pass
        return "保持热爱，奔赴山海。"

    def send_tg_notification(self, message):
        """发送 Telegram 通知（FIX#10 北京时间；FIX#11 改用 HTML 模式避免 Markdown 转义炸雷）"""
        if not self.tg_config or not self.tg_config.get("bot_token") or not self.tg_config.get("chat_id"):
            return

        url = f"https://api.telegram.org/bot{self.tg_config['bot_token']}/sendMessage"

        hitokoto = self.get_hitokoto()
        now = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() + TZ_OFFSET_SECONDS))
        formatted_message = (
            "☁️ <b>HidenCloud 自动续费任务</b>\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"👤 <b>账号</b>: <code>{html.escape(self.username)}</code>\n"
            f"💰 <b>余额</b>: <code>{html.escape(self.balance)}</code>\n"
            f"🕒 <b>时间</b>: <code>{now}</code> (UTC+8)\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"{message}\n"
            "━━━━━━━━━━━━━━━━━━\n"
            f"💡 <b>每日一言</b>:\n<i>{html.escape(hitokoto)}</i>"
        )

        payload = {
            "chat_id": self.tg_config["chat_id"],
            "text": formatted_message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                logger.info("Telegram 通知发送成功")
            else:
                hint = ""
                if "can't send messages to the bot" in (resp.text or ""):
                    hint = ("（提示：TG_CHAT_ID 填成了机器人自己的 ID，机器人不能给自己发消息；"
                            "请联系 @userinfobot 获取你自己的数字 ID）")
                logger.error(f"Telegram 通知发送失败: {resp.text}{hint}")
        except Exception as e:
            logger.error(f"发送 Telegram 通知出错: {e}")

    # ----------------------------------------------------------
    # CSRF
    # ----------------------------------------------------------
    def get_csrf_token(self, url=None, html=None):
        """从页面或 HTML 中提取 CSRF Token"""
        try:
            if html is None and url:
                resp = self.session.get(url, timeout=HTTP_TIMEOUT)
                html = resp.text

            if not html:
                return None

            soup = BeautifulSoup(html, 'html.parser')
            token_meta = soup.find('meta', attrs={'name': 'csrf-token'})
            if token_meta:
                self.csrf_token = token_meta.get('content')
                return self.csrf_token

            token_input = soup.find('input', attrs={'name': '_token'})
            if token_input:
                self.csrf_token = token_input.get('value')
                return self.csrf_token
        except Exception as e:
            logger.error(f"获取 CSRF Token 失败: {e}")
        return self.csrf_token

    # ----------------------------------------------------------
    # 登录检查（FIX#1: 核心修复——区分失败原因）
    # ----------------------------------------------------------
    def check_login(self):
        """检查登录状态并获取用户名。
        返回 True/False；失败时 self.fail_reason 给出精确原因：
          cookie_rejected      - 被重定向到 /login（cookie 过期/复制不完整）
          cloudflare_blocked   - CF 挑战/拦截（HTTP 403/503 或挑战页特征）
          http_<code>          - 其他 HTTP 错误
          exception            - 网络异常
        """
        self.fail_reason = ""
        try:
            resp = self.session.get(f"{self.base_url}/dashboard",
                                    timeout=HTTP_TIMEOUT, allow_redirects=True)
            body_head = (resp.text or "")[:300]

            # 1) 被重定向到登录页 = 服务端明确拒绝 cookie（真正的"cookie 失效"）
            if "/login" in resp.url:
                self.fail_reason = f"cookie_rejected（被重定向到 {resp.url}）"
                return False

            # 2) Cloudflare 挑战/拦截（修复前与 cookie 失效混为同一句报错）
            low = body_head.lower()
            if resp.status_code in (403, 503) or any(m in low for m in CF_MARKERS):
                self.fail_reason = (f"cloudflare_blocked（HTTP {resp.status_code}, url={resp.url}）"
                                    f" 响应片段: {body_head[:150]!r}")
                return False

            # 3) 其他非 200
            if resp.status_code != 200:
                self.fail_reason = (f"http_{resp.status_code}（url={resp.url}）"
                                    f" 响应片段: {body_head[:150]!r}")
                return False

            self.dashboard_html = resp.text  # FIX#14: 复用，避免 get_service_ids 重复请求
            soup = BeautifulSoup(resp.text, 'html.parser')
            # 刷新 CSRF
            self.get_csrf_token(html=resp.text)

            # 提取用户名 - 优先找 Email
            email_tag = soup.select_one('p.font-light.text-gray-500')
            if not email_tag:
                email_tag = soup.find('p', string=re.compile(r'.+@.+\..+'))

            if email_tag and "[email" not in email_tag.get_text():
                self.username = email_tag.get_text().strip()
            else:
                # 备选：查找用户名链接 (通常是真实姓名)
                name_tag = soup.select_one('h3 > a[href="#"]')
                if name_tag:
                    self.username = name_tag.get_text().strip()
                elif email_tag:
                    self.username = email_tag.get_text().strip()

            # 提取余额 - 查找包含金额的卡片
            balance_link = soup.select_one('a[href*="/balance"]')
            if balance_link:
                balance_tag = balance_link.find(['dt', 'h4', 'div'], class_=re.compile(r'font-extrabold|text-3xl'))
                if balance_tag:
                    self.balance = balance_tag.get_text().strip()

            if self.balance == "未知":
                # 兜底：正则搜索货币符号
                balance_text = soup.find(string=re.compile(r'(¥|€|余额)\s*\d+\.\d+'))
                if balance_text:
                    self.balance = balance_text.strip()

            logger.info(f"✅ 账号 {self.username} 登录成功 (余额: {self.balance})")
            return True
        except Exception as e:
            self.fail_reason = f"exception: {e!r}"
            logger.error(f"登录状态检查异常: {e}")
        return False

    def get_service_ids(self):
        """获取所有服务 ID（FIX#14: 复用 check_login 已获取的页面）"""
        logger.info("正在获取服务列表...")
        try:
            page_html = self.dashboard_html
            if page_html is None:
                resp = self.session.get(f"{self.base_url}/dashboard", timeout=HTTP_TIMEOUT)
                page_html = resp.text
            ids = re.findall(r'service/(\d+)/manage', page_html)
            return list(set(ids))
        except Exception as e:
            logger.error(f"获取服务 ID 失败: {e}")
            return []

    def renew_service(self, service_id):
        """对指定服务进行续期"""
        logger.info(f"正在为服务 {service_id} 申请续期...")
        manage_url = f"{self.base_url}/service/{service_id}/manage"

        # 获取管理页面并提取 Token
        resp = self.session.get(manage_url, timeout=HTTP_TIMEOUT)
        token = self.get_csrf_token(html=resp.text)
        if not token:
            return False, "获取续期 Token 失败"

        renew_url = f"{self.base_url}/service/{service_id}/renew"
        data = {
            "_token": token,
            "days": "7"
        }
        # 添加 XSRF Token 支持
        xsrf_token = self.session.cookies.get("XSRF-TOKEN")
        headers = {
            "Referer": manage_url,
            "Origin": self.base_url,
            "X-CSRF-TOKEN": token
        }
        if xsrf_token:
            from urllib.parse import unquote
            headers["X-XSRF-TOKEN"] = unquote(xsrf_token)

        try:
            resp = self.session.post(renew_url, data=data, headers=headers, timeout=HTTP_TIMEOUT)
            # 如果跳转到了账单页，或者响应中包含成功信息，说明续期申请成功
            if "invoice" in resp.url or "payment" in resp.url:
                return True, "申请成功"

            # 检查页面是否包含错误信息
            soup_res = BeautifulSoup(resp.text, 'html.parser')
            alert = soup_res.find(['div', 'span'], attrs={'role': 'alert'})
            if alert:
                alert_text = alert.get_text(strip=True)
                if "only renew" in alert_text or "expires in" in alert_text:
                    # 提取剩余天数
                    days_match = re.search(r'expires in (\d+) days', alert_text)
                    days_info = f" (剩余 {days_match.group(1)} 天)" if days_match else ""
                    return True, f"未到期{days_info}"
                return False, f"申请失败: {alert_text}"

            if resp.status_code == 200 and "dash.hidencloud.com/service" in resp.url:
                # 仍在管理页但没报错，可能是已经申请过或者其他情况
                return True, "状态正常"

            return False, f"续期请求失败: {resp.status_code}"
        except Exception as e:
            return False, f"续期异常: {e}"

    # ----------------------------------------------------------
    # 账单支付（FIX#7 未支付识别；FIX#8 成功判定）
    # ----------------------------------------------------------
    @staticmethod
    def _is_unpaid_row(parent_text):
        """FIX#7: 行是否未支付。原逻辑关键词含 'Invoice'，已支付行也含该词 → 误伤。"""
        if PAID_RE.search(parent_text):
            return False
        return bool(UNPAID_RE.search(parent_text))

    @staticmethod
    def _pay_succeeded(resp):
        """FIX#8: 支付成功判定。原逻辑 status_code==200 即算成功（重渲染表单页会误判）。"""
        text = resp.text or ""
        low = text.lower()
        url = resp.url or ""
        # 失败信号优先
        if any(m in low for m in ("insufficient", "余额不足", "payment failed", "支付失败", "付款失败")):
            return False
        # 成功信号：跳到账单页且显示已支付，或页面有明确成功提示
        # 同样用 \bpaid\b 防止 "unpaid"（无未付账单提示）造成误判
        if "/invoice/" in url and re.search(r'\bpaid\b', low):
            return True
        if any(m in text for m in ("支付成功", "付款成功", "Payment successful", "Payment Success")):
            return True
        return False

    def pay_unpaid_invoices(self, service_id):
        """检测并支付未支付订单"""
        logger.info(f"正在检查服务 {service_id} 的待支付订单...")
        invoice_list_url = f"{self.base_url}/service/{service_id}/invoices?where=unpaid"
        try:
            resp = self.session.get(invoice_list_url, timeout=HTTP_TIMEOUT)
            # 查找所有账单链接
            soup = BeautifulSoup(resp.text, 'html.parser')
            invoice_links = []

            for a in soup.find_all('a', href=True):
                href = a['href']
                if '/invoice/' in href and 'download' not in href:
                    parent = a.find_parent(['tr', 'div', 'li'])
                    if parent:
                        parent_text = parent.get_text()
                        if self._is_unpaid_row(parent_text):
                            invoice_links.append(href)

            if not invoice_links:
                return True, "无待支付订单"

            success_count = 0
            fail_count = 0
            invoice_links = list(set(invoice_links))  # 去重

            for inv_link in invoice_links:
                if not inv_link.startswith('http'):
                    inv_link = self.base_url + inv_link

                logger.info(f"  └ 正在处理账单页面: {inv_link.split('/')[-1]}")
                inv_resp = self.session.get(inv_link, timeout=HTTP_TIMEOUT)
                inv_soup = BeautifulSoup(inv_resp.text, 'html.parser')

                # 寻找支付表单
                pay_form = None
                for form in inv_soup.find_all('form'):
                    action = form.get('action', '')
                    # 排除充值表单
                    if 'balance/add' in action:
                        continue

                    # 查找提交按钮
                    btn = form.find(['button', 'input'], attrs={'type': 'submit'})
                    if not btn:
                        btn = form.find('button')

                    if btn and ('支付' in btn.get_text() or 'Pay' in btn.get_text() or '确认' in btn.get_text()):
                        pay_form = form
                        break

                if not pay_form:
                    # 降级尝试：寻找任何包含 invoice 或 payment 的表单
                    for form in inv_soup.find_all('form'):
                        action = form.get('action', '')
                        if 'invoice' in action or 'payment' in action:
                            pay_form = form
                            break

                if pay_form:
                    action = pay_form.get('action', '')
                    if not action.startswith('http'):
                        action = self.base_url + action

                    # 提取表单数据
                    payload = {}
                    for inp in pay_form.find_all('input'):
                        name = inp.get('name')
                        if name:
                            payload[name] = inp.get('value', '')

                    # 补充 Token
                    token = self.get_csrf_token(html=inv_resp.text)
                    if token:
                        payload['_token'] = token

                    headers = {
                        "Referer": inv_link,
                        "X-CSRF-TOKEN": token or self.csrf_token
                    }

                    pay_resp = self.session.post(action, data=payload, headers=headers, timeout=HTTP_TIMEOUT)
                    if self._pay_succeeded(pay_resp):
                        success_count += 1
                        logger.info("    ✅ 支付成功")
                    else:
                        fail_count += 1
                        logger.warning(f"    ❌ 支付未确认成功 (HTTP {pay_resp.status_code}, url={pay_resp.url})")
                else:
                    fail_count += 1
                    logger.warning("    ⚠️ 未能在账单页找到支付按钮，请检查页面结构")

            return fail_count == 0, f"支付完成 ({success_count}/{len(invoice_links)} 成功)"

        except Exception as e:
            return False, f"支付异常: {e}"

    # ----------------------------------------------------------
    # 主任务（FIX#1 失败归因；FIX#2 失败标记）
    # ----------------------------------------------------------
    def run_task(self):
        """运行完整续费任务"""
        if not self.check_login():
            logger.error(f"❌ 登录验证失败 [{self.fail_reason}]")
            if "cloudflare_blocked" in self.fail_reason:
                advice = ("❌ <b>Cloudflare 拦截了本次出口 IP</b>\n"
                          "GitHub Actions 的数据中心 IP 经常被 CF 挑战。"
                          "Cookie 本身可能有效——可在本机运行验证；若本机成功，需要更换续期通道。")
            elif "cookie_rejected" in self.fail_reason:
                advice = ("❌ <b>Cookie 已被服务端拒绝</b>（过期或复制不完整）\n"
                          "请按 README 重新抓取 Cookie（只需 hidencloud_session 等必要项，不要带 cf_clearance），"
                          "并更新仓库 Secret HIDEN_COOKIE。")
            else:
                advice = f"❌ <b>无法访问 Dashboard</b>\n失败原因: {html.escape(self.fail_reason)}"
            self.send_tg_notification(advice)
            self.task_failed = True
            return

        logger.info(f"账号 {self.username} 登录验证通过，开始执行任务...")
        service_ids = self.get_service_ids()
        if not service_ids:
            logger.warning("未找到任何活跃服务")
            return

        results = []
        success_count = 0
        fail_count = 0

        for s_id in service_ids:
            r_success, r_msg = self.renew_service(s_id)
            p_success, p_msg = self.pay_unpaid_invoices(s_id)

            status_icon = "✅" if r_success and p_success else "❌"
            results.append(
                f"{status_icon} <b>服务 {s_id}</b>\n"
                f"   └ 续期: <code>{html.escape(str(r_msg))}</code>\n"
                f"   └ 支付: <code>{html.escape(str(p_msg))}</code>"
            )

            if r_success and p_success:
                success_count += 1
            else:
                fail_count += 1

        summary = f"📊 <b>执行统计</b>: 成功 <code>{success_count}</code> | 失败 <code>{fail_count}</code>\n\n"
        report = summary + "\n".join(results)

        logger.info(f"任务完成报告:\n{report}")
        self.send_tg_notification(report)

        if fail_count:
            self.task_failed = True

        # 检查并更新 Cookie（FIX#6: 规范化比较 + 只同步非 CF cookie）
        new_cookie_str = self.get_cookie_string()
        old_cookie_str = self._normalize_cookie_string(self.cookie_str)
        if new_cookie_str and new_cookie_str != old_cookie_str:
            logger.info("检测到 Cookie 已刷新，准备同步到本地及 GitHub Secrets")

            # 1. 更新 GitHub Secrets
            self.update_github_secret(new_cookie_str)

            # 2. 更新本地 config.json (如果运行在本地)
            self.update_local_config(new_cookie_str)

    def update_local_config(self, new_cookie):
        """同步更新本地 config.json"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(current_dir, "config.json")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config_data = json.load(f)

                # 寻找并更新匹配的账号
                updated = False
                for acc in config_data.get("accounts", []):
                    # 通过 cookie_str 的部分内容或用户名匹配 (简单处理：如果只有一个账号就直接更)
                    if acc.get("cookie_str") == self.cookie_str or len(config_data.get("accounts", [])) == 1:
                        acc["cookie_str"] = new_cookie
                        updated = True
                        break

                if updated:
                    with open(config_path, 'w') as f:
                        json.dump(config_data, f, indent=4, ensure_ascii=False)
                    logger.info("✅ 本地 config.json 已同步更新")
            except Exception as e:
                logger.error(f"更新本地 config.json 失败: {e}")


def main():
    config = {}
    # 按照参考项目逻辑：从环境变量 HIDEN_COOKIE 读取
    env_cookies = os.environ.get("HIDEN_COOKIE")

    # 兼容本地 config.json
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(current_dir, "config.json")

    if env_cookies:
        logger.info("从环境变量 HIDEN_COOKIE 加载账号信息")
        account_cookies = split_accounts(env_cookies)  # FIX(T5)
    elif os.path.exists(config_path):
        logger.info("从本地 config.json 加载账号信息")
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                accounts = config.get("accounts", [])
                account_cookies = []
                for acc in accounts:
                    if acc.get("cookie_str"):
                        account_cookies.append(acc.get("cookie_str"))
                    elif acc.get("cookies"):
                        # 兼容字典格式
                        if isinstance(acc["cookies"], dict):
                            c_str = "; ".join([f"{k}={v}" for k, v in acc["cookies"].items()])
                        else:
                            c_str = str(acc["cookies"])
                        account_cookies.append(c_str)
        except Exception as e:
            logger.error(f"读取 config.json 失败: {e}")
            sys.exit(1)
    else:
        logger.error("未找到 HIDEN_COOKIE 环境变量或 config.json")
        sys.exit(1)

    # TG 配置
    tg_config = {
        "bot_token": os.environ.get("TG_BOT_TOKEN") or config.get("telegram", {}).get("bot_token"),
        "chat_id": os.environ.get("TG_CHAT_ID") or config.get("telegram", {}).get("chat_id")
    }

    total = 0
    failed = 0
    for cookie_str in account_cookies:
        if not cookie_str.strip():
            continue
        total += 1
        try:
            bot = HidenCloud(cookie_str, tg_config)
            bot.run_task()
            if bot.task_failed:
                failed += 1
        except Exception as e:
            failed += 1
            logger.error(f"处理账号时发生异常: {e}")

    # FIX#2: 有失败就以非零退出，让 GitHub Action 显示红色而不是假绿
    if total == 0:
        logger.error("没有可运行的账号")
        sys.exit(1)
    if failed:
        logger.error(f"⚠️ {failed}/{total} 个账号任务失败")
        sys.exit(1)
    logger.info(f"全部 {total} 个账号任务完成")


if __name__ == "__main__":
    main()
