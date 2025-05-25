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
                prompt_hash = hashlib.sha256(
                    clean_text(content).encode("utf-8")
                ).hexdigest()

                tags_list: list[str] = [
                    tag["name"] for tag in prompt_data.get("tags", [])
                ]

                all_extracted_prompts.append(
                    {
                        "title": title,
                        "author": author_name,
                        "tags": tags_list,
                        "content": content,
                        "hash": prompt_hash,
                    }
                )

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
            prompt_hash = hashlib.sha256(
                clean_text(content).encode("utf-8")
            ).hexdigest()

            all_extracted_prompts.append(
                {
                    "title": title,
                    "author": author_name,
                    "tags": tags_list,
                    "content": content,
                    "hash": prompt_hash,
                }
            )

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


def clean_text(text: str | dict) -> str:
    return "".join(str(text).split())


if __name__ == "__main__":
    os.makedirs("public", exist_ok=True)
    joestar_market = JoestarMarket()
    vmoranv_market = VmoranvMarket()
    moderator = ContentModerator()
    cleaned_prompts = set()
    existing_prompts = set()
    blacklist = set()

    output_file = "public/prompts.json"
    blacklist_file = "blacklist.txt"

    if os.path.exists(output_file):
        print("读取现有提示词文件...")
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                existing_prompts_a = json.load(f)
                for prompt in existing_prompts_a:
                    existing_prompts.add(
                        clean_text(
                            f"{prompt['title']}{prompt['author']}{prompt['tags']}{prompt['content']}"
                        )
                    )
            print(f"已读取 {len(existing_prompts)} 条现有提示词")
        except Exception as e:
            print(f"读取现有提示词文件失败: {e!s}")

    try:
        with open(blacklist_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.startswith("#"):
                    blacklist.add(line.strip())
        print(f"已读取 {len(blacklist)} 条黑名单")
    except Exception as e:
        print(f"读取黑名单文件失败: {e!s}")

    all_prompts = []
    all_prompts.extend(joestar_market.get_prompts())
    all_prompts.extend(vmoranv_market.get_prompts())

    print(f"总共获取到 {len(all_prompts)} 条提示词")

    compliant_prompts = []
    for prompt in all_prompts:
        clean_content = clean_text(
            f"{prompt['title']}{prompt['author']}{prompt['tags']}{prompt['content']}"
        )
        prompt_hash = hashlib.sha256(clean_text(prompt['content']).encode("utf-8")).hexdigest()
        
        if prompt_hash in blacklist:
            print(f"{prompt['title']}: 在黑名单中，跳过")
            continue

        if clean_content in cleaned_prompts:
            print(f"{prompt['title']}: 重复，跳过")
            continue
        if clean_content in existing_prompts:
            print(f"{prompt['title']}: 已存在，跳过")
            compliant_prompts.append(prompt)
            continue
        cleaned_prompts.add(clean_content)

        if not moderator.check_text(clean_content):
            print(f"{prompt['title']}: 内容不合规，跳过")
            continue

        compliant_prompts.append(prompt)

    if len(compliant_prompts) != 0:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(compliant_prompts, f, ensure_ascii=False, indent=2)

        unique_authors = {prompt["author"] for prompt in compliant_prompts}
        all_tags = [tag for prompt in compliant_prompts for tag in prompt["tags"]]
        unique_tags = {tag for tag in all_tags}

        stats = {
            "total_prompts": len(compliant_prompts),
            "total_authors": len(unique_authors),
            "total_tags": len(unique_tags),
            "tag_frequency": {tag: all_tags.count(tag) for tag in unique_tags},
            "last_updated": datetime.timestamp(datetime.now()),
        }

        with open("public/info.json", "w", encoding="utf-8") as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)

    print(f"完成，合规提示词共 {len(compliant_prompts)} 条")
