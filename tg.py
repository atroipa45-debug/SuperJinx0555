"""Minimal, fast Telegram Bot API client on top of a shared aiohttp session."""
import asyncio
import json

import aiohttp


class TGError(Exception):
    def __init__(self, code, desc):
        super().__init__(f"{code}: {desc}")
        self.code = code
        self.desc = desc or ""


class TG:
    def __init__(self, token, session):
        self.token = token
        self.s = session
        self.base = f"https://api.telegram.org/bot{token}/"

    async def call(self, method, _files=None, **params):
        params = {k: v for k, v in params.items() if v is not None}
        long_poll = method == "getUpdates"
        for attempt in range(4):
            try:
                if _files:
                    form = aiohttp.FormData()
                    for k, v in params.items():
                        form.add_field(k, v if isinstance(v, str) else json.dumps(v, ensure_ascii=False))
                    for k, (fname, data) in _files.items():
                        form.add_field(k, data, filename=fname)
                    req = self.s.post(self.base + method, data=form, timeout=aiohttp.ClientTimeout(total=120))
                else:
                    req = self.s.post(self.base + method, json=params,
                                      timeout=aiohttp.ClientTimeout(total=75 if long_poll else 30))
                async with req as resp:
                    d = await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
                if attempt == 3:
                    raise TGError(0, f"network: {e.__class__.__name__}")
                await asyncio.sleep(1 + attempt)
                continue
            if d.get("ok"):
                return d["result"]
            code = d.get("error_code", 0)
            if code == 429:
                await asyncio.sleep((d.get("parameters") or {}).get("retry_after", 3) + 0.3)
                continue
            raise TGError(code, d.get("description", ""))
        raise TGError(0, "retries exceeded")

    async def download(self, file_id):
        f = await self.call("getFile", file_id=file_id)
        url = f"https://api.telegram.org/file/bot{self.token}/{f['file_path']}"
        async with self.s.get(url, timeout=aiohttp.ClientTimeout(total=60)) as r:
            return await r.read(), r.headers.get("Content-Type", "application/octet-stream")
