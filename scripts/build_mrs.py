#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import gzip
import shutil
import hashlib
import tempfile
import subprocess
import urllib.request
from pathlib import Path
from urllib.parse import urlparse, unquote

ROOT_DIR = Path(__file__).resolve().parents[1]
LINKS_FILE = ROOT_DIR / "links.txt"
OUT_DIR = ROOT_DIR / "rule" / "mihomo"
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", str(ROOT_DIR / "bin" / "mihomo"))

OUT_DIR.mkdir(parents=True, exist_ok=True)

DOMAIN_KEYWORDS = (
    "geosite",
    "domain",
    "domains",
    "site",
)

IPCIDR_KEYWORDS = (
    "geoip",
    "ipcidr",
    "ip-cidr",
    "cidr",
    "ip",
)


def log(msg: str) -> None:
    print(f"[build-mrs] {msg}", flush=True)


def read_links() -> list[str]:
    if not LINKS_FILE.exists():
        raise SystemExit("找不到 links.txt")

    links: list[str] = []

    for raw in LINKS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw.strip()

        if not line:
            continue

        if line.startswith("#"):
            continue

        # 只取链接本体，允许行尾写注释
        # 例如：https://example.com/a.yaml # comment
        line = line.split(" #", 1)[0].strip()

        if not line.startswith(("http://", "https://")):
            log(f"跳过非链接行: {line}")
            continue

        links.append(line)

    if not links:
        raise SystemExit("links.txt 没有有效链接")

    return links


def filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    name = Path(unquote(parsed.path)).name

    if not name:
        digest = hashlib.sha256(url.encode()).hexdigest()[:12]
        name = f"rules-{digest}.yaml"

    # 去掉常见压缩后缀
    for suffix in (".gz", ".gzip"):
        if name.lower().endswith(suffix):
            name = name[: -len(suffix)]

    # 清理非法文件名字符
    name = re.sub(r"[^\w.\-]+", "_", name)

    return name


def output_name_from_url(url: str) -> str:
    filename = filename_from_url(url)

    lower = filename.lower()

    for suffix in (".yaml", ".yml", ".txt", ".list", ".conf"):
        if lower.endswith(suffix):
            return filename[: -len(suffix)] + ".mrs"

    return filename + ".mrs"


def input_format_from_url(url: str) -> str:
    filename = filename_from_url(url).lower()

    if filename.endswith((".yaml", ".yml")):
        return "yaml"

    if filename.endswith((".txt", ".list", ".conf")):
        return "text"

    # 默认按 yaml 处理，MetaCubeX 规则集多数是 yaml
    return "yaml"


def download(url: str, dst: Path) -> None:
    log(f"下载: {url}")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "mihomo-mrs-auto-convert/1.0",
            "Accept": "*/*",
        },
    )

    with urllib.request.urlopen(req, timeout=60) as resp:
        data = resp.read()

    if url.lower().endswith((".gz", ".gzip")):
        data = gzip.decompress(data)

    dst.write_bytes(data)


def detect_type_from_url(url: str) -> str | None:
    lower = url.lower()

    # geoip/private.yaml 这种直接识别成 ipcidr
    if any(k in lower for k in IPCIDR_KEYWORDS):
        return "ipcidr"

    # geosite/category-xxx.yaml 这种直接识别成 domain
    if any(k in lower for k in DOMAIN_KEYWORDS):
        return "domain"

    return None


def detect_type_from_content(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore")

    domain_hits = 0
    ip_hits = 0

    for raw in text.splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        # YAML payload 项
        if line.startswith("- "):
            line = line[2:].strip()

        line_upper = line.upper()

        if any(
            line_upper.startswith(prefix)
            for prefix in (
                "IP-CIDR,",
                "IP-CIDR6,",
                "IP-ASN,",
                "GEOIP,",
            )
        ):
            ip_hits += 3
            continue

        if any(
            line_upper.startswith(prefix)
            for prefix in (
                "DOMAIN,",
                "DOMAIN-SUFFIX,",
                "DOMAIN-KEYWORD,",
                "GEOSITE,",
                "FULL:",
                "DOMAIN:",
                "DOMAIN-SUFFIX:",
                "DOMAIN-KEYWORD:",
            )
        ):
            domain_hits += 3
            continue

        # 纯 CIDR
        if re.search(r"(^|,)\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}($|,)", line):
            ip_hits += 2
            continue

        if ":" in line and "/" in line and re.search(r"[0-9a-fA-F:]+/\d{1,3}", line):
            ip_hits += 2
            continue

        # 普通域名
        if re.search(r"(^|\s)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}($|\s)", line):
            domain_hits += 1
            continue

    if ip_hits > domain_hits:
        return "ipcidr"

    return "domain"


def run_convert(rule_type: str, input_format: str, input_file: Path, output_file: Path) -> None:
    tmp_output = output_file.with_suffix(output_file.suffix + ".tmp")

    if tmp_output.exists():
        tmp_output.unlink()

    cmd = [
        MIHOMO_BIN,
        "convert-ruleset",
        rule_type,
        input_format,
        str(input_file),
        str(tmp_output),
    ]

    log("执行: " + " ".join(cmd))

    subprocess.run(cmd, check=True)

    tmp_output.replace(output_file)

    log(f"生成: {output_file.relative_to(ROOT_DIR)}")


def main() -> None:
    if not Path(MIHOMO_BIN).exists():
        raise SystemExit(f"找不到 mihomo: {MIHOMO_BIN}")

    links = read_links()

    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)

        used_outputs: set[str] = set()

        for index, url in enumerate(links, start=1):
            filename = filename_from_url(url)
            input_file = tmpdir / filename

            download(url, input_file)

            input_format = input_format_from_url(url)

            rule_type = detect_type_from_url(url)
            if rule_type is None:
                rule_type = detect_type_from_content(input_file)

            output_name = output_name_from_url(url)

            # 防止多个链接文件名一样互相覆盖
            if output_name in used_outputs:
                stem = Path(output_name).stem
                output_name = f"{stem}-{index}.mrs"

            used_outputs.add(output_name)

            output_file = OUT_DIR / output_name

            log(f"识别: {filename} -> type={rule_type}, format={input_format}, output={output_name}")

            run_convert(rule_type, input_format, input_file, output_file)

    log("全部完成")


if __name__ == "__main__":
    main()
