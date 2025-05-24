import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote_plus

import requests


class JoestarMarket:
    @staticmethod
    def _fetch_page(skip_items: int) -> list[dict[str, Any]] | None:
        params = {
            "skip": skip_items,
            "limit": 16,
            "is_r18": 0,
        }
        try:
            response = requests.get(
                "http://www.jasongjz.top:8000/api/v1/prompts/",
                params=params,
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"获取数据失败: {e!s}")
            return None

    def get_prompts(self) -> list[dict[str, Any]]:
        all_extracted_prompts: list[dict[str, Any]] = []
        current_skip: int = 0

        print("开始获取 JoestarMarket prompts...")

        while True:
            prompts_on_page = self._fetch_page(current_skip)

            if prompts_on_page is None or not prompts_on_page:
                break

            for prompt_data in prompts_on_page:
                if not isinstance(prompt_data, dict):
                    continue

                title: str = prompt_data.get("title", "无标题")
                content: str = prompt_data.get("content", "无内容")
                owner_info: dict[str, Any] = prompt_data.get("owner", {})
                author_name: str = owner_info.get("username", "匿名用户")

                tags_list: list[str] = [tag["name"] for tag in prompt_data.get("tags", [])]

                all_extracted_prompts.append({
                    "title": title,
                    "author": author_name,
                    "tags": tags_list,
                    "content": content,
                })

            current_skip += 16
            time.sleep(0.3)

        print(f"获取完成，共 {len(all_extracted_prompts)} 条提示词")
        return all_extracted_prompts


class VmoranvMarket:
    @staticmethod
    def _fetch_all() -> list[dict[str, Any]] | None:
        try:
            response = requests.get(
                "https://prompt.614447.xyz/api/prompts",
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"获取VmoranvMarket数据失败: {e!s}")
            return None

    def get_prompts(self) -> list[dict[str, Any]]:
        all_extracted_prompts: list[dict[str, Any]] = []

        print("开始获取 VmoranvMarket prompts...")
        prompts_data: dict = self._fetch_all()
        prompts_data: dict = prompts_data.get("data", {})

        if not prompts_data:
            return all_extracted_prompts

        for prompt_data in prompts_data:
            if not isinstance(prompt_data, dict):
                continue
            
            if prompt_data.get("status") != "published":
                continue

            title: str = prompt_data.get("title", "无标题")
            content: str = prompt_data.get("content", "无内容")
            author_info: dict[str, Any] = prompt_data.get("author", {})
            author_name: str = author_info.get("name", "匿名用户")
            tags_list: list[str] = prompt_data.get("tags", [])

            all_extracted_prompts.append({
                "title": title,
                "author": author_name,
                "tags": tags_list,
                "content": content,
            })

        print(f"VmoranvMarket获取完成，共 {len(all_extracted_prompts)} 条提示词")
        return all_extracted_prompts


class ContentModerator:
    def __init__(self):
        self.access_key_id = os.getenv("ALIYUN_ACCESS_KEY_ID")
        self.access_key_secret = os.getenv("ALIYUN_ACCESS_KEY_SECRET")
        self.endpoint = "https://green-cip.cn-shanghai.aliyuncs.com"

    @staticmethod
    def _split_text(content: str) -> list[str]:
        """超长文本分割"""
        if not content:
            return []
        chunks = []
        for i in range(0, len(content), 600):
            chunks.append(content[i : i + 600])
        return chunks

    def _check_single_text(self, content: str) -> bool:
        """单段文本审核"""
        try:
            params_a: dict[str, str] = {
                "Format": "JSON",
                "Version": "2022-03-02",
                "AccessKeyId": self.access_key_id,
                "SignatureMethod": "HMAC-SHA1",
                "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "SignatureVersion": "1.0",
                "SignatureNonce": str(uuid.uuid4()),
                "Action": "TextModerationPlus",
                "Service": "comment_detection_pro",
                "ServiceParameters": json.dumps({"content": content}),
            }

            sorted_params: list = sorted(params_a.items())

            def encode_a(s) -> str:
                return (
                    quote_plus(str(s))
                    .replace("+", "%20")
                    .replace("*", "%2A")
                    .replace("%7E", "~")
                )

            canonicalized_query = "&".join(
                f"{encode_a(k)}={encode_a(v)}" for k, v in sorted_params
            )
            string_to_sign = f"POST&{encode_a('/')}&{encode_a(canonicalized_query)}"
            key = self.access_key_secret + "&"
            signature = base64.b64encode(
                hmac.new(
                    key.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha1
                ).digest()
            ).decode("utf-8")

            params_a["Signature"] = signature

            response = requests.post(self.endpoint, params=params_a)
            if response.status_code != 200:
                print(f"内容审核HTTP状态错误: {response.status_code}")
                return False

            result = response.json()
            if "Data" not in result:
                print(f"内容审核返回数据异常: {result}")
                return False

            risk_level = result["Data"].get("RiskLevel", "").lower()
            return risk_level != "high"

        except requests.RequestException as e:
            print(f"内容审核网络请求错误: {e!s}")
            return False
        except Exception as e:
            print(f"内容审核发生未知错误: {e!s}")
            return False

    def check_text(self, content: str) -> bool:
        """所有文本审核"""
        try:
            if not content:
                return True

            if len(content) <= 600:
                return self._check_single_text(content)

            chunks = self._split_text(content)
            results = [self._check_single_text(chunk) for chunk in chunks]
            return all(results)
        except Exception as e:
            print(f"内容审核过程发生错误: {e!s}")
            return False


if __name__ == "__main__":
    joestar_market = JoestarMarket()
    vmoranv_market = VmoranvMarket()
    moderator = ContentModerator()
    cleaned_prompts = set()
    compliant_prompts = []

    def clean_text(text: str) -> str:
        return "".join(text.split())

    all_prompts = []
    all_prompts.extend(joestar_market.get_prompts())
    all_prompts.extend(vmoranv_market.get_prompts())
    
    print(f"总共获取到 {len(all_prompts)} 条提示词")

    for prompt in all_prompts:
        clean_title = clean_text(prompt["title"])
        clean_author = clean_text(prompt["author"])
        clean_content = clean_text(prompt["content"])
        
        if clean_content in cleaned_prompts:
            print(f"{clean_title}: 内容重复，跳过")
            continue
        cleaned_prompts.add(clean_content)
        
        checks = [
            (clean_title, "标题"),
            (clean_author, "作者"),
            (clean_content, "内容")
        ]
        
        is_compliant = True
        for text, type_name in checks:
            if not moderator.check_text(text):
                print(f"{clean_title}: {type_name}不合规")
                is_compliant = False
                break
        
        if not is_compliant:
            continue

        compliant_tags = []
        for tag in prompt["tags"]:
            clean_tag = clean_text(tag)
            if moderator.check_text(clean_tag):
                compliant_tags.append(tag)
            else:
                print(f"标签不合规: {tag}")
        prompt["tags"] = compliant_tags

        compliant_prompts.append(prompt)

    output_file = "public/prompts.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(compliant_prompts, f, ensure_ascii=False, indent=2)
    
    print(f"完成，合规提示词共 {len(compliant_prompts)} 条，已保存至 {output_file}")
