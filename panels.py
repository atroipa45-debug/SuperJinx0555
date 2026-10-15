"""Adapters for VPN management panels.

Supported: Marzban (and compatible forks), Marzneshin, 3x-ui (Sanaei), X-UI (Alireza),
Hiddify Manager (API v2), any custom HTTP API, and a manual config stock that works with any panel.
Every adapter exposes: test(), create(), renew(), usage(), delete().
"""
import asyncio
import base64
import datetime
import json
import math
import secrets
import time
import urllib.parse
import uuid

import aiohttp

GB = 1024 ** 3
_AUTH = {}  # cached tokens / cookies: key -> (value, expires)

TYPES = {
    "marzban": "Marzban",
    "marzneshin": "Marzneshin",
    "xui": "3x-ui (Sanaei)",
    "xui_alireza": "X-UI (Alireza)",
    "hiddify": "Hiddify Manager",
    "custom": "API سفارشی (هر پنل دیگر)",
    "stock": "کانفیگ دستی (انبار کانفیگ)",
}


class PanelError(Exception):
    pass


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def _from_iso(s):
    if not s:
        return 0
    try:
        return int(datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


class Base:
    def __init__(self, srv, session):
        self.srv = srv
        self.s = session
        self.url = (srv.get("url") or "").rstrip("/")
        self.user = srv.get("username") or ""
        self.pw = srv.get("password") or ""
        ex = srv.get("extra") or {}
        self.extra = json.loads(ex) if isinstance(ex, str) else ex
        self.ssl = False if self.extra.get("insecure", True) else True

    async def req(self, method, path, **kw):
        kw.setdefault("timeout", aiohttp.ClientTimeout(total=20))
        kw.setdefault("ssl", self.ssl)
        url = path if path.startswith("http") else self.url + path
        try:
            async with self.s.request(method, url, **kw) as r:
                txt = await r.text()
                try:
                    data = json.loads(txt) if txt else {}
                except ValueError:
                    data = {"_raw": txt[:300]}
                cookies = {k: v.value for k, v in r.cookies.items()}
                return r.status, data, cookies
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise PanelError(f"اتصال به سرور برقرار نشد ({e.__class__.__name__})")

    @staticmethod
    def err(d, default="خطا در پنل"):
        if isinstance(d, dict):
            for k in ("detail", "msg", "message", "error"):
                if d.get(k):
                    v = d[k]
                    return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)[:200]
        return default

    async def test(self):
        raise NotImplementedError

    async def create(self, name, gb, days, users=1):
        raise NotImplementedError

    async def renew(self, meta, gb, expire_ts, users=1):
        raise NotImplementedError

    async def usage(self, meta):
        raise NotImplementedError

    async def delete(self, meta):
        raise NotImplementedError


# ---------------------------------------------------------------- Marzban
class Marzban(Base):
    TOKEN_PATH = "/api/admin/token"

    async def token(self, force=False):
        k = (self.TOKEN_PATH, self.url, self.user)
        t = _AUTH.get(k)
        if t and not force and t[1] > time.time():
            return t[0]
        st, d, _ = await self.req("POST", self.TOKEN_PATH, data={"username": self.user, "password": self.pw})
        if st != 200 or "access_token" not in d:
            raise PanelError("ورود به پنل ناموفق بود (نام کاربری یا رمز عبور اشتباه است)")
        _AUTH[k] = (d["access_token"], time.time() + 3000)
        return d["access_token"]

    async def api(self, method, path, **kw):
        for i in range(2):
            h = {"Authorization": "Bearer " + await self.token(force=i > 0)}
            st, d, _ = await self.req(method, path, headers=h, **kw)
            if st == 401 and i == 0:
                continue
            return st, d
        raise PanelError("احراز هویت پنل ناموفق بود")

    def sub(self, d):
        u = d.get("subscription_url") or ""
        if u and not u.startswith("http"):
            u = self.url + u
        return u

    async def test(self):
        await self.token(True)
        st, d = await self.api("GET", "/api/system")
        if st == 200:
            return f"اتصال موفق | کاربران: {d.get('total_user', '-')} | فعال: {d.get('users_active', '-')}"
        # reseller (non-sudo) admin accounts cannot read /api/system
        st, d = await self.api("GET", "/api/admin")
        if st != 200:
            raise PanelError(self.err(d))
        return f"اتصال موفق با اکانت نمایندگی ({d.get('username', self.user)})"

    async def _inbounds(self):
        inb = self.extra.get("inbounds")
        if not inb:
            st, d = await self.api("GET", "/api/inbounds")
            if st != 200:
                raise PanelError(self.err(d))
            inb = {p: [i["tag"] for i in lst] for p, lst in d.items()}
        proxies = {}
        for p in inb:
            proxies[p] = {"flow": self.extra["flow"]} if p == "vless" and self.extra.get("flow") else {}
        return proxies, inb

    async def create(self, name, gb, days, users=1):
        proxies, inb = await self._inbounds()
        body = {
            "username": name, "proxies": proxies, "inbounds": inb,
            "data_limit": int(gb * GB) if gb else 0,
            "expire": int(time.time() + days * 86400) if days else 0,
            "data_limit_reset_strategy": "no_reset", "status": "active", "note": "",
        }
        st, d = await self.api("POST", "/api/user", json=body)
        if st not in (200, 201):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود"))
        return {"link": self.sub(d) or "\n".join(d.get("links") or []), "meta": {"name": name}}

    async def renew(self, meta, gb, expire_ts, users=1):
        n = meta["name"]
        st, d = await self.api("PUT", f"/api/user/{n}", json={
            "data_limit": int(gb * GB) if gb else 0, "expire": int(expire_ts) if expire_ts else 0, "status": "active"})
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))
        await self.api("POST", f"/api/user/{n}/reset")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/api/user/{meta['name']}")
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        return {"used": d.get("used_traffic") or 0, "total": d.get("data_limit") or 0,
                "expire": d.get("expire") or 0, "status": d.get("status"), "link": self.sub(d)}

    async def delete(self, meta):
        await self.api("DELETE", f"/api/user/{meta['name']}")


# ---------------------------------------------------------------- Marzneshin
class Marzneshin(Marzban):
    TOKEN_PATH = "/api/admins/token"

    async def test(self):
        await self.token(True)
        st, d = await self.api("GET", "/api/services")
        if st != 200:
            raise PanelError(self.err(d))
        return f"اتصال موفق | سرویس‌ها: {len(d.get('items', d) if isinstance(d, dict) else d)}"

    async def _services(self):
        ids = self.extra.get("service_ids")
        if ids:
            return [int(x) for x in ids]
        st, d = await self.api("GET", "/api/services")
        items = d.get("items", []) if isinstance(d, dict) else d
        return [i["id"] for i in items]

    def _body(self, name, gb, expire_ts, ids):
        b = {"username": name, "service_ids": ids, "data_limit": int(gb * GB) if gb else 0,
             "data_limit_reset_strategy": "no_reset", "note": ""}
        if expire_ts:
            b.update(expire_strategy="fixed_date", expire_date=_iso(expire_ts))
        else:
            b.update(expire_strategy="never")
        return b

    async def create(self, name, gb, days, users=1):
        ids = await self._services()
        st, d = await self.api("POST", "/api/users", json=self._body(name, gb, time.time() + days * 86400 if days else 0, ids))
        if st not in (200, 201):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود"))
        return {"link": self.sub(d), "meta": {"name": name}}

    async def renew(self, meta, gb, expire_ts, users=1):
        ids = await self._services()
        st, d = await self.api("PUT", f"/api/users/{meta['name']}", json=self._body(meta["name"], gb, expire_ts, ids))
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))
        await self.api("POST", f"/api/users/{meta['name']}/reset")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/api/users/{meta['name']}")
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        return {"used": d.get("used_traffic") or 0, "total": d.get("data_limit") or 0,
                "expire": _from_iso(d.get("expire_date")), "status": "active" if d.get("enabled", True) else "disabled",
                "link": self.sub(d)}

    async def delete(self, meta):
        await self.api("DELETE", f"/api/users/{meta['name']}")


# ---------------------------------------------------------------- 3x-ui / x-ui
class XUI(Base):
    PREFIX = "/panel/api/inbounds"

    async def login(self, force=False):
        k = ("xui", self.url, self.user)
        t = _AUTH.get(k)
        if t and not force and t[1] > time.time():
            return t[0]
        st, d, ck = await self.req("POST", "/login", data={"username": self.user, "password": self.pw})
        if not (isinstance(d, dict) and d.get("success")) or not ck:
            raise PanelError("ورود به پنل ناموفق بود (نام کاربری یا رمز عبور اشتباه است)")
        cookie = "; ".join(f"{a}={b}" for a, b in ck.items())
        _AUTH[k] = (cookie, time.time() + 3000)
        return cookie

    async def api(self, method, path, **kw):
        for i in range(2):
            ck = await self.login(force=i > 0)
            st, d, _ = await self.req(method, self.PREFIX + path, headers={"Cookie": ck, "Accept": "application/json"}, **kw)
            if i == 0 and (st in (401, 404) or "_raw" in d):
                continue
            return st, d
        raise PanelError("احراز هویت پنل ناموفق بود")

    async def test(self):
        await self.login(True)
        st, d = await self.api("GET", "/list")
        if not d.get("success"):
            raise PanelError(self.err(d))
        return f"اتصال موفق | اینباندها: {len(d.get('obj') or [])}"

    async def _iid(self):
        if self.extra.get("inbound_id"):
            return int(self.extra["inbound_id"])
        st, d = await self.api("GET", "/list")
        obj = d.get("obj") or []
        if not obj:
            raise PanelError("هیچ اینباندی در پنل وجود ندارد")
        return obj[0]["id"]

    async def _inbound(self, iid):
        st, d = await self.api("GET", f"/get/{iid}")
        if not d.get("success"):
            raise PanelError("اینباند یافت نشد")
        return d["obj"]

    def _host(self):
        return self.extra.get("host") or urllib.parse.urlparse(self.url).hostname

    def build_link(self, inb, client):
        """Best-effort direct link for vless / vmess / trojan inbounds."""
        try:
            proto = inb["protocol"]
            ss = json.loads(inb.get("streamSettings") or "{}")
            net = ss.get("network", "tcp")
            sec = ss.get("security", "none")
            host = self._host()
            port = inb["port"]
            q = {"type": net, "security": sec}
            if net == "ws":
                ws = ss.get("wsSettings", {})
                q["path"] = ws.get("path", "/")
                h = ws.get("host") or (ws.get("headers") or {}).get("Host")
                if h:
                    q["host"] = h
            elif net == "grpc":
                q["serviceName"] = ss.get("grpcSettings", {}).get("serviceName", "")
            elif net in ("httpupgrade", "xhttp", "splithttp"):
                st = ss.get(net + "Settings", {})
                q["path"] = st.get("path", "/")
                if st.get("host"):
                    q["host"] = st["host"]
            if sec == "tls":
                tl = ss.get("tlsSettings", {})
                if tl.get("serverName"):
                    q["sni"] = tl["serverName"]
                q["fp"] = (tl.get("settings") or {}).get("fingerprint", "chrome")
            elif sec == "reality":
                rs = ss.get("realitySettings", {})
                st = rs.get("settings", {})
                q["pbk"] = st.get("publicKey", "")
                q["fp"] = st.get("fingerprint", "chrome")
                q["sni"] = (rs.get("serverNames") or [""])[0]
                q["sid"] = (rs.get("shortIds") or [""])[0]
                if st.get("spiderX"):
                    q["spx"] = st["spiderX"]
            if client.get("flow"):
                q["flow"] = client["flow"]
            tag = urllib.parse.quote(client["email"])
            qs = urllib.parse.urlencode({k: v for k, v in q.items() if v not in (None, "")})
            if proto == "vless":
                return f"vless://{client['id']}@{host}:{port}?{qs}#{tag}"
            if proto == "trojan":
                return f"trojan://{client['password']}@{host}:{port}?{qs}#{tag}"
            if proto == "vmess":
                v = {"v": "2", "ps": client["email"], "add": host, "port": str(port), "id": client["id"], "aid": "0",
                     "net": net, "type": "none", "host": q.get("host", ""), "path": q.get("path", q.get("serviceName", "")),
                     "tls": sec if sec != "none" else "", "sni": q.get("sni", "")}
                return "vmess://" + base64.b64encode(json.dumps(v).encode()).decode()
        except Exception:
            return ""
        return ""

    def _client(self, proto, name, gb, expire_ts, users, cid=None, sub=None):
        c = {"email": name, "limitIp": int(users or 0), "totalGB": int(gb * GB) if gb else 0,
             "expiryTime": int(expire_ts * 1000) if expire_ts else 0, "enable": True, "tgId": "",
             "subId": sub or secrets.token_hex(8), "reset": 0}
        cid = cid or str(uuid.uuid4())
        if proto in ("trojan", "shadowsocks"):
            c["password"] = cid
        else:
            c["id"] = cid
            c["flow"] = self.extra.get("flow", "")
        if proto == "shadowsocks":
            c["method"] = ""
        return c, cid

    async def create(self, name, gb, days, users=1):
        iid = await self._iid()
        inb = await self._inbound(iid)
        client, cid = self._client(inb["protocol"], name, gb, time.time() + days * 86400 if days else 0, users)
        st, d = await self.api("POST", "/addClient", data={"id": str(iid), "settings": json.dumps({"clients": [client]})})
        if not d.get("success"):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود"))
        sub_base = (self.extra.get("sub_url") or "").rstrip("/")
        link = f"{sub_base}/{client['subId']}" if sub_base else self.build_link(inb, client)
        return {"link": link, "meta": {"name": name, "uuid": cid, "iid": iid, "proto": inb["protocol"], "sub": client["subId"]}}

    async def renew(self, meta, gb, expire_ts, users=1):
        client, _ = self._client(meta.get("proto", "vless"), meta["name"], gb, expire_ts, users, meta["uuid"], meta.get("sub"))
        st, d = await self.api("POST", f"/updateClient/{meta['uuid']}",
                               data={"id": str(meta["iid"]), "settings": json.dumps({"clients": [client]})})
        if not d.get("success"):
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))
        await self.api("POST", f"/{meta['iid']}/resetClientTraffic/{meta['name']}")

    async def usage(self, meta):
        st, d = await self.api("GET", f"/getClientTraffics/{meta['name']}")
        o = d.get("obj")
        if not o:
            raise PanelError("سرویس در پنل یافت نشد")
        exp = o.get("expiryTime") or 0
        return {"used": (o.get("up") or 0) + (o.get("down") or 0), "total": o.get("total") or 0,
                "expire": int(exp / 1000) if exp > 0 else 0, "status": "active" if o.get("enable") else "disabled"}

    async def delete(self, meta):
        await self.api("POST", f"/{meta['iid']}/delClient/{meta['uuid']}")


class XUIAlireza(XUI):
    PREFIX = "/xui/API/inbounds"


# ---------------------------------------------------------------- Hiddify
class Hiddify(Base):
    def h(self):
        return {"Hiddify-API-Key": self.extra.get("api_key") or self.pw, "Accept": "application/json"}

    async def test(self):
        st, d, _ = await self.req("GET", "/api/v2/panel/ping/", headers=self.h())
        if st != 200:
            raise PanelError("اتصال ناموفق بود؛ لینک ادمین یا API Key را بررسی کنید")
        return "اتصال موفق به Hiddify"

    def _link(self, uid):
        base = (self.extra.get("client_url") or self.url).rstrip("/")
        return f"{base}/{uid}/"

    async def create(self, name, gb, days, users=1):
        body = {"name": name, "usage_limit_GB": gb or 10000, "package_days": days or 3650, "mode": "no_reset", "enable": True}
        st, d, _ = await self.req("POST", "/api/v2/admin/user/", headers=self.h(), json=body)
        if st not in (200, 201) or not d.get("uuid"):
            raise PanelError(self.err(d, "ساخت کاربر در پنل ناموفق بود"))
        return {"link": self._link(d["uuid"]), "meta": {"name": name, "uuid": d["uuid"]}}

    async def renew(self, meta, gb, expire_ts, users=1):
        days = max(1, math.ceil((expire_ts - time.time()) / 86400)) if expire_ts else 3650
        st, d, _ = await self.req("PATCH", f"/api/v2/admin/user/{meta['uuid']}/", headers=self.h(), json={
            "usage_limit_GB": gb or 10000, "package_days": days, "current_usage_GB": 0, "start_date": None, "enable": True})
        if st != 200:
            raise PanelError(self.err(d, "تمدید در پنل ناموفق بود"))

    async def usage(self, meta):
        st, d, _ = await self.req("GET", f"/api/v2/admin/user/{meta['uuid']}/", headers=self.h())
        if st != 200:
            raise PanelError("سرویس در پنل یافت نشد")
        exp = 0
        if d.get("start_date"):
            try:
                sd = datetime.datetime.strptime(d["start_date"], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
                exp = int(sd.timestamp() + (d.get("package_days") or 0) * 86400)
            except ValueError:
                pass
        return {"used": int((d.get("current_usage_GB") or 0) * GB), "total": int((d.get("usage_limit_GB") or 0) * GB),
                "expire": exp, "status": "active" if d.get("enable", True) else "disabled", "link": self._link(meta["uuid"])}

    async def delete(self, meta):
        await self.req("DELETE", f"/api/v2/admin/user/{meta['uuid']}/", headers=self.h())


# ---------------------------------------------------------------- Custom HTTP API
class Custom(Base):
    """Bridge for any panel: POST {url} with JSON {action, ...} and Authorization: Bearer <password>.
    create -> {"link": "...", "meta": {...}} ; usage -> {"used": bytes, "total": bytes, "expire": unix}"""

    async def call(self, action, **kw):
        st, d, _ = await self.req("POST", "", json={"action": action, **kw}, headers={"Authorization": "Bearer " + self.pw})
        if st != 200 or (isinstance(d, dict) and d.get("error")):
            raise PanelError(self.err(d, "پاسخ نامعتبر از API"))
        return d

    async def test(self):
        await self.call("ping")
        return "اتصال موفق به API"

    async def create(self, name, gb, days, users=1):
        d = await self.call("create", username=name, volume_gb=gb, days=days, users=users)
        return {"link": d.get("link", ""), "meta": {"name": name, **(d.get("meta") or {})}}

    async def renew(self, meta, gb, expire_ts, users=1):
        await self.call("renew", meta=meta, volume_gb=gb, expire=int(expire_ts or 0), users=users)

    async def usage(self, meta):
        return await self.call("usage", meta=meta)

    async def delete(self, meta):
        await self.call("delete", meta=meta)


class Stock(Base):
    async def test(self):
        return "انبار کانفیگ دستی (نیازی به اتصال ندارد)"

    async def usage(self, meta):
        raise PanelError("آمار مصرف برای کانفیگ دستی در دسترس نیست")

    async def renew(self, meta, gb, expire_ts, users=1):
        raise PanelError("تمدید خودکار برای کانفیگ دستی امکان‌پذیر نیست")

    async def delete(self, meta):
        return None


ADAPTERS = {"marzban": Marzban, "marzneshin": Marzneshin, "xui": XUI, "xui_alireza": XUIAlireza,
            "hiddify": Hiddify, "custom": Custom, "stock": Stock}


def get_adapter(srv, session):
    cls = ADAPTERS.get(srv.get("type"))
    if not cls:
        raise PanelError("نوع پنل پشتیبانی نمی‌شود")
    return cls(srv, session)
