"""
Interfaces to interact with various LLMs
"""

import json
import os
import atexit
from typing import Dict, Optional, List
import yaml
from openai import OpenAI
import httpx  # openai 1.x 依赖 httpx，直接使用没问题

CONFIG = "/home/xuehuanhuan/2.LATTE/project_ghost/config.yaml"
with open(CONFIG, "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)
api_key = cfg.get("OPENAI_API_KEY")
modela = cfg.get("MODEL", "gpt-5.1")
def _make_openai_client() -> OpenAI:
    """
    适配 openai==1.28.1：
    - 清理会触发 SDK 误传 `proxies` 的环境变量；
    - 默认不走代理；如需代理，可在 config.ini 的 [LLM] 增加 proxy=...（可留空）。
    """
    api_key = cfg.get("OPENAI_API_KEY")
    base_url = cfg.get("API_BASE", "")
    return OpenAI(api_key=api_key, base_url=base_url)


class QueryChatGPT:
    """Interface for interacting with ChatGPT"""

    def __init__(self,special=0) -> None:
        self.total_prompt_tokens = 0
        self.total_completion_tokens = 0
        self.total_tokens = 0
        self.chat_context: List[Dict[str, str]] = []
        self.chat_history: List[Dict[str, str]] = []
        self.temperature: float = 0.2
        self.use_history = False
        self.system_prompt: Optional[str] = None
        self.special=special
       # atexit.register(self.log_history)

    def clear(self):
        self.chat_context = []

    def set_history(self, open: bool) -> None:
        self.use_history = open

    def insert_system_prompt(self, system_prompt: str) -> None:
        if self.chat_context and self.chat_context[0]["role"] == "system":
            self.chat_context[0]["content"] = system_prompt
        else:
            self.chat_context.insert(0, {"role": "system", "content": system_prompt})

    def log_history(self, log_file: str = "chat_log.json"):
        if not os.path.exists(log_file):
            with open(log_file, "w") as w:
                json.dump([], w, indent=4)
        with open(log_file, "r") as r:
            log = json.load(r)
        assert isinstance(log, list)
        log.append(self.chat_history)
        with open(log_file, "w") as w:
            json.dump(log, w, indent=4)

    def __query(self, prompt: str, model: str) -> Optional[str]:
        self.chat_context.append({"role": "user", "content": prompt})
        self.chat_history.append({"role": "user", "content": prompt})

        client = _make_openai_client()
        response = client.chat.completions.create(
            messages=self.chat_context,
            model=model,
            temperature=self.temperature,
        )
        response_content = str(response.choices[0].message.content)
        if hasattr(response, "usage") and response.usage:
            self.total_prompt_tokens += response.usage.prompt_tokens
            self.total_completion_tokens += response.usage.completion_tokens
            self.total_tokens += response.usage.total_tokens
        self.chat_context.append({"role": "assistant", "content": response_content})
        self.chat_history.append({"role": "assistant", "content": response_content})
        return response_content

    def token_used(self):
        return self.total_prompt_tokens, self.total_completion_tokens, self.total_tokens

    def query(self, prompt: str, *, model: str = "gpt-4o-mini") -> Optional[str]:
        if self.special==1:
            model="gpt-4.1"
        model="openai/gpt-5.1-codex"
        response = self.__query(prompt, model)
        if not self.use_history:
            self.clear()
        return response
