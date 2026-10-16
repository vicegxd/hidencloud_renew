import json
import logging
import os
import re
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

class HidenCloud:
    def __init__(self, cookie_str, tg_config=None):
        self.base_url = "https://dash.hidencloud.com"
        self.cookie_str = cookie_str
        self.tg_config = tg_config
        self.session = requests.Session(impersonate="chrome110")
        self.username = "Unknown"
        self.balance = "未知"
        self.updated_cookies = False
        self.csrf_token = ""
        self.parse_and_set_cookies()

    def parse_and_set_cookies(self):
        """解析 Cookie 字符串并设置到 Session"""
        if not self.cookie_str:
            return
        
        cookies = {}
        # 改进解析，处理可能存在的引号或复杂值
        for item in self.cookie_str.split(';'):
            if '=' in item:
                parts = item.strip().split('=', 1)
                if len(parts) == 2:
                    key, value = parts
                    cookies[key] = value
        self.session.cookies.update(cookies)

    def get_cookie_string(self):
        """获取当前的 Cookie 字符串 (确保捕获所有域名的 Cookie)"""
        cookie_list = []
        # items() 返回的是 (name, value) 元组
        for name, value in self.session.cookies.items():
            cookie_list.append(f"{name}={value}")
        return "; ".join(cookie_list)

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
        """发送 Telegram 通知"""
        if not self.tg_config or not self.tg_config.get("bot_token") or not self.tg_config.get("chat_id"):
            return

        url = f"https://api.telegram.org/bot{self.tg_config['bot_token']}/sendMessage"
        
        hitokoto = self.get_hitokoto()
        # 优化通知排版
        formatted_message = (
            f"☁️ **HidenCloud 自动续费任务**\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"👤 **账号**: `{self.username}`\n"
            f"💰 **余额**: `{self.balance}`\n"
            f"🕒 **时间**: `{time.strftime('%Y-%m-%d %H:%M:%S')}`\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"{message}\n"
            f"━━━━━━━━━━━━━━━━━━\n"
            f"💡 **每日一言**:\n_{hitokoto}_"
        )

        payload = {
            "chat_id": self.tg_config["chat_id"],
            "text": formatted_message,
            "parse_mode": "Markdown"
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                logger.info("Telegram 通知发送成功")
            else:
                logger.error(f"Telegram 通知发送失败: {resp.text}")
        except Exception as e:
            logger.error(f"发送 Telegram 通知出错: {e}")

    def get_csrf_token(self, url=None, html=None):
        """从页面或 HTML 中提取 CSRF Token"""
        try:
            if html is None and url:
                resp = self.session.get(url, timeout=20)
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

    def check_login(self):
        """检查登录状态并获取用户名"""
        try:
            resp = self.session.get(f"{self.base_url}/dashboard", timeout=20, allow_redirects=True)
            if "/login" in resp.url:
                return False
                
            if resp.status_code == 200:
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
            logger.error(f"登录状态检查异常: {e}")
        return False

    def get_service_ids(self):
        """获取所有服务 ID"""
        logger.info("正在获取服务列表...")
        try:
            resp = self.session.get(f"{self.base_url}/dashboard", timeout=20)
            ids = re.findall(r'service/(\d+)/manage', resp.text)
            return list(set(ids))
        except Exception as e:
            logger.error(f"获取服务 ID 失败: {e}")
            return []

    def renew_service(self, service_id):
        """对指定服务进行续期"""
        logger.info(f"正在为服务 {service_id} 申请续期...")
        manage_url = f"{self.base_url}/service/{service_id}/manage"
        
        # 获取管理页面并提取 Token
        resp = self.session.get(manage_url, timeout=20)
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
            resp = self.session.post(renew_url, data=data, headers=headers, timeout=20)
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

    def pay_unpaid_invoices(self, service_id):
        """检测并支付未支付订单"""
        logger.info(f"正在检查服务 {service_id} 的待支付订单...")
        invoice_list_url = f"{self.base_url}/service/{service_id}/invoices?where=unpaid"
        try:
            resp = self.session.get(invoice_list_url, timeout=20)
            # 查找所有账单链接 (使用 BeautifulSoup 过滤通知栏链接)
            soup = BeautifulSoup(resp.text, 'html.parser')
            invoice_links = []
            
            # 查找所有的 a 标签
            for a in soup.find_all('a', href=True):
                href = a['href']
                if '/invoice/' in href and 'download' not in href:
                    # 检查父容器是否包含 "Unpaid" 或 "待支付"
                    parent = a.find_parent(['tr', 'div', 'li'])
                    if parent:
                        parent_text = parent.get_text()
                        if any(kw in parent_text for kw in ['Unpaid', '待支付', '未支付', '待付款', "Invoice"]):
                            invoice_links.append(href)
            
            if not invoice_links:
                return True, "无待支付订单"

            success_count = 0
            invoice_links = list(set(invoice_links)) # 去重
            
            for inv_link in invoice_links:
                if not inv_link.startswith('http'):
                    inv_link = self.base_url + inv_link
                
                logger.info(f"  └ 正在处理账单页面: {inv_link.split('/')[-1]}")
                inv_resp = self.session.get(inv_link, timeout=20)
                inv_soup = BeautifulSoup(inv_resp.text, 'html.parser')
                
                # 寻找支付表单
                pay_form = None
                for form in inv_soup.find_all('form'):
                    action = form.get('action', '')
                    # 排除充值表单
                    if 'balance/add' in action: continue
                    
                    # 查找提交按钮
                    btn = form.find(['button', 'input'], attrs={'type': 'submit'})
                    if not btn: btn = form.find('button')
                    
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
                    if token: payload['_token'] = token
                    
                    headers = {
                        "Referer": inv_link,
                        "X-CSRF-TOKEN": token or self.csrf_token
                    }
                    
                    pay_resp = self.session.post(action, data=payload, headers=headers, timeout=20)
                    if "成功" in pay_resp.text or "Success" in pay_resp.text or pay_resp.status_code == 200:
                        success_count += 1
                        logger.info("    ✅ 支付成功")
                    else:
                        logger.warning(f"    ❌ 支付失败 (状态码: {pay_resp.status_code})")
                else:
                    logger.warning("    ⚠️ 未能在账单页找到支付按钮，请检查页面结构")

            return True, f"支付完成 ({success_count}/{len(invoice_links)} 成功)"
        except Exception as e:
            return False, f"支付异常: {e}"

    def run_task(self):
        """运行完整续费任务"""
        if not self.check_login():
            logger.error("❌ Cookie 已失效或无法访问 Dashboard")
            self.send_tg_notification("❌ Cookie 已失效，请重新提取并更新 GitHub Secrets")
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
            results.append(f"{status_icon} **服务 {s_id}**\n   └ 续期: `{r_msg}`\n   └ 支付: `{p_msg}`")
            
            if r_success and p_success:
                success_count += 1
            else:
                fail_count += 1

        summary = f"📊 **执行统计**: 成功 `{success_count}` | 失败 `{fail_count}`\n\n"
        report = summary + "\n".join(results)
        
        logger.info(f"任务完成报告:\n{report}")
        self.send_tg_notification(report)

        # 检查并更新 Cookie
        new_cookie_str = self.get_cookie_string()
        if new_cookie_str != self.cookie_str:
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
    config_cookies = []
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(current_dir, "config.json")
    
    if env_cookies:
        logger.info("从环境变量 HIDEN_COOKIE 加载账号信息")
        # 支持 & 或 换行符 分隔多账号
        account_cookies = re.split(r'[&\n]', env_cookies)
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
            return
    else:
        logger.error("未找到 HIDEN_COOKIE 环境变量或 config.json")
        return

    # TG 配置
    tg_config = {
        "bot_token": os.environ.get("TG_BOT_TOKEN") or config.get("telegram", {}).get("bot_token"),
        "chat_id": os.environ.get("TG_CHAT_ID") or config.get("telegram", {}).get("chat_id")
    }

    for cookie_str in account_cookies:
        if not cookie_str.strip(): continue
        try:
            bot = HidenCloud(cookie_str, tg_config)
            bot.run_task()
        except Exception as e:
            logger.error(f"处理账号时发生异常: {e}")

if __name__ == "__main__":
    main()
