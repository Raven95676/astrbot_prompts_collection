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

# Configuration constants
JOESTAR_API_URL = "http://www.jasongjz.top:8000/api/v1/prompts/"
VMORANV_API_URL = "https://prompt.614447.xyz/api/prompts"
ALIYUN_ENDPOINT = "https://green-cip.cn-shanghai.aliyuncs.com"
REQUEST_TIMEOUT = 10
TEXT_CHUNK_SIZE = 600
SLEEP_INTERVAL = 0.3

# File paths
OUTPUT_DIR = "public"
OUTPUT_FILE = "public/prompts.json"
INFO_FILE = "public/info.json"
BLACKLIST_FILE = "blacklist.txt"


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
                JOESTAR_API_URL,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"获取JoestarMarket数据失败: {e!s}")
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

                prompt = self._extract_prompt_data(prompt_data)
                all_extracted_prompts.append(prompt)

            current_skip += 16
            time.sleep(SLEEP_INTERVAL)

        print(f"JoestarMarket获取完成，共 {len(all_extracted_prompts)} 条提示词")
        return all_extracted_prompts

    @staticmethod
    def _extract_prompt_data(prompt_data: dict[str, Any]) -> dict[str, Any]:
        title: str = prompt_data.get("title", "无标题")
        content: str = prompt_data.get("content", "无内容")
        owner_info: dict[str, Any] = prompt_data.get("owner", {})
        author_name: str = owner_info.get("username", "匿名用户")
        if author_name == "default_user":
            author_name = "匿名用户"
        tags_list: list[str] = [tag["name"] for tag in prompt_data.get("tags", [])]
        prompt_hash = get_hash(content)

        return {
            "title": title,
            "author": author_name,
            "tags": tags_list,
            "content": content,
            "hash": prompt_hash,
        }


class VmoranvMarket:
    @staticmethod
    def _fetch_all() -> dict[str, Any] | None:
        try:
            response = requests.get(
                VMORANV_API_URL,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"获取VmoranvMarket数据失败: {e!s}")
            return None

    def get_prompts(self) -> list[dict[str, Any]]:
        all_extracted_prompts: list[dict[str, Any]] = []

        print("开始获取 VmoranvMarket prompts...")
        response_data = self._fetch_all()

        if not response_data:
            return all_extracted_prompts

        prompts_data = response_data.get("data", [])

        for prompt_data in prompts_data:
            if not isinstance(prompt_data, dict):
                continue

            if prompt_data.get("status") != "published":
                continue

            prompt = self._extract_prompt_data(prompt_data)
            all_extracted_prompts.append(prompt)

        print(f"VmoranvMarket获取完成，共 {len(all_extracted_prompts)} 条提示词")
        return all_extracted_prompts

    @staticmethod
    def _extract_prompt_data(prompt_data: dict[str, Any]) -> dict[str, Any]:
        title: str = prompt_data.get("title", "无标题")
        content: str = prompt_data.get("content", "无内容")
        author_info: dict[str, Any] = prompt_data.get("author", {})
        author_name: str = author_info.get("name", "匿名用户")
        tags_list: list[str] = prompt_data.get("tags", [])
        prompt_hash = get_hash(content)

        return {
            "title": title,
            "author": author_name,
            "tags": tags_list,
            "content": content,
            "hash": prompt_hash,
        }


class ContentModerator:
    def __init__(self):
        self.access_key_id = os.getenv("ALIYUN_ACCESS_KEY_ID")
        self.access_key_secret = os.getenv("ALIYUN_ACCESS_KEY_SECRET")

        if not self.access_key_id or not self.access_key_secret:
            raise ValueError(
                "请设置环境变量 ALIYUN_ACCESS_KEY_ID 和 ALIYUN_ACCESS_KEY_SECRET"
            )

    @staticmethod
    def _split_text(content: str) -> list[str]:
        """超长文本分割"""
        if not content:
            return []
        return [
            content[i : i + TEXT_CHUNK_SIZE]
            for i in range(0, len(content), TEXT_CHUNK_SIZE)
        ]

    def _check_single_text(self, content: str) -> bool:
        """单段文本审核"""

        try:
            params = self._build_request_params(content)
            signature = self._generate_signature(params)
            params["Signature"] = signature

            response = requests.post(
                ALIYUN_ENDPOINT, params=params, timeout=REQUEST_TIMEOUT
            )
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

    def _build_request_params(self, content: str) -> dict[str, str]:
        """构建请求参数"""
        return {
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

    def _generate_signature(self, params: dict[str, str]) -> str:
        """生成签名"""
        sorted_params = sorted(params.items())

        def encode_param(s) -> str:
            return (
                quote_plus(str(s))
                .replace("+", "%20")
                .replace("*", "%2A")
                .replace("%7E", "~")
            )

        canonicalized_query = "&".join(
            f"{encode_param(k)}={encode_param(v)}" for k, v in sorted_params
        )
        string_to_sign = f"POST&{encode_param('/')}&{encode_param(canonicalized_query)}"
        key = self.access_key_secret + "&"

        return base64.b64encode(
            hmac.new(
                key.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha1
            ).digest()
        ).decode("utf-8")

    def check_text(self, content: str) -> bool:
        """文本内容审核"""
        try:
            if not content:
                return True

            if len(content) <= TEXT_CHUNK_SIZE:
                return self._check_single_text(content)

            chunks = self._split_text(content)
            return all(self._check_single_text(chunk) for chunk in chunks)
        except Exception as e:
            print(f"内容审核过程发生错误: {e!s}")
            return False


def clean_text(text: str | dict) -> str:
    """清理文本，移除空白字符"""
    return "".join(str(text).split())


def get_hash(text: str | dict) -> str:
    """生成文本哈希值"""
    return hashlib.sha256(clean_text(text).encode("utf-8")).hexdigest()


def load_existing_prompts(file_path: str) -> set[str]:
    """加载现有提示词哈希集合"""
    if not os.path.exists(file_path):
        return set()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            existing_prompts_data = json.load(f)
            return {get_hash(prompt["content"]) for prompt in existing_prompts_data}
    except Exception as e:
        print(f"读取现有提示词文件失败: {e!s}")
        return set()


def load_blacklist(file_path: str) -> set[str]:
    """加载黑名单"""
    if not os.path.exists(file_path):
        return set()

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return {
                line.strip() for line in f if line.strip() and not line.startswith("#")
            }
    except Exception as e:
        print(f"读取黑名单文件失败: {e!s}")
        return set()


def process_prompts(
    all_prompts: list[dict[str, Any]],
    existing_prompts: set[str],
    blacklist: set[str],
    moderator: ContentModerator,
) -> list[dict[str, Any]]:
    """处理提示词，去重、审核和过滤"""
    compliant_prompts = []
    cleaned_prompts = {}

    for prompt in all_prompts:
        clean_content = clean_text(prompt["content"])
        prompt_hash = get_hash(clean_content)

        # 检查黑名单
        if prompt_hash in blacklist:
            print(f"{prompt['title']}: 在黑名单中，跳过")
            continue

        # 检查重复
        if prompt_hash in cleaned_prompts:
            existing_prompt = cleaned_prompts[prompt_hash]

            if (
                existing_prompt["author"] == "匿名用户"
                and prompt["author"] != "匿名用户"
            ):
                existing_prompt["author"] = prompt["author"]

            existing_tags = set(existing_prompt["tags"])
            new_tags = set(prompt["tags"])
            if new_tags - existing_tags:
                existing_prompt["tags"] = list(existing_tags | new_tags)

            print(f"{prompt['title']}: 重复")
            continue
        cleaned_prompts[prompt_hash] = prompt

        # 检查是否已存在
        if prompt_hash in existing_prompts:
            compliant_prompts.append(prompt)
            print(f"{prompt['title']}: 已存在，跳过")
            continue

        # 内容审核
        if not moderator.check_text(clean_content):
            print(f"{prompt['title']}: 内容不合规，跳过")
            continue

        compliant_prompts.append(prompt)

    return compliant_prompts


def save_results(
    prompts: list[dict[str, Any]], output_file: str, info_file: str
) -> None:
    """保存结果到文件"""
    if not prompts:
        print("没有合规的提示词需要保存")
        return

    # 保存提示词
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(prompts, f, ensure_ascii=False, indent=2)

    # 生成统计信息
    unique_authors = {prompt["author"] for prompt in prompts}
    all_tags = [tag for prompt in prompts for tag in prompt["tags"]]
    unique_tags = set(all_tags)

    stats = {
        "total_prompts": len(prompts),
        "total_authors": len(unique_authors),
        "total_tags": len(unique_tags),
        "tag_frequency": {tag: all_tags.count(tag) for tag in unique_tags},
        "last_updated": datetime.timestamp(datetime.now()),
    }

    with open(info_file, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)


def main() -> None:
    """主函数"""
    # 创建输出目录
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 初始化组件
    joestar_market = JoestarMarket()
    vmoranv_market = VmoranvMarket()
    moderator = ContentModerator()

    # 加载现有数据
    existing_prompts = load_existing_prompts(OUTPUT_FILE)
    blacklist = load_blacklist(BLACKLIST_FILE)

    print(f"已读取 {len(existing_prompts)} 条现有提示词")
    print(f"已读取 {len(blacklist)} 条黑名单")

    # 获取所有提示词
    all_prompts = []
    all_prompts.extend(joestar_market.get_prompts())
    all_prompts.extend(vmoranv_market.get_prompts())

    print(f"总共获取到 {len(all_prompts)} 条提示词")

    # 处理提示词
    compliant_prompts = process_prompts(
        all_prompts, existing_prompts, blacklist, moderator
    )

    # 保存结果
    save_results(compliant_prompts, OUTPUT_FILE, INFO_FILE)

    print(f"完成，合规提示词共 {len(compliant_prompts)} 条")


if __name__ == "__main__":
    main()
