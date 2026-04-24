#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import gzip
import hashlib
import ipaddress
import os
import re
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from urllib.parse import unquote, urlparse


ROOT_DIR = Path(__file__).resolve().parents[1]
LINKS_FILE = ROOT_DIR / "links.txt"
OUT_DIR = ROOT_DIR / "rule" / "mihomo"
MIHOMO_BIN = os.environ.get("MIHOMO_BIN", str(ROOT_DIR / "bin" / "mihomo"))

OUT_DIR.mkdir(parents=True, exist_ok=True)


DOMAIN_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "HOST",
    "HOST-SUFFIX",
    "HOST-KEYWORD",
}

IP_RULE_TYPES = {
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "SRC-IP-CIDR6",
}


SKIP_RULE_TYPES = {
    "GEOIP",
    "GEOSITE",
    "IP-ASN",
    "SRC-IP-ASN",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-PATH-REGEX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "NETWORK",
    "UID",
    "RULE-SET",
    "SUB-RULE",
    "MATCH",
}


def log(message: str) -> None:
    print(f"[build-rules] {message}", flush=True)


def die(message: str) -> None:
    raise SystemExit(f"[build-rules] ERROR: {message}")


def read_links() -> list[str]:
    if not LINKS_FILE.exists():
        die("找不到 links.txt")

    links: list[str] = []

    for raw in LINKS_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        # 允许行尾注释：
        # https://example.com/a.yaml # comment
        line = line.split(" #", 1)[0].strip()

        # 兼容旧写法：
        # https://example.com/a.yaml|name|domain
        # 现在只取链接本体，输出名自动从 URL 文件名识别
        line = line.split("|", 1)[0].strip()

        if not line.startswith(("https://", "http://")):
            log(f"跳过非链接行: {line}")
            continue

        links.append(line)

    if not links:
        die("links.txt 没有有效链接")

    return links


def filename_from_url(url: str) -> str:
    parsed = urlparse(url)
    filename = Path(unquote(parsed.path)).name

    if not filename:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:12]
        filename = f"rules-{digest}.txt"

    lower = filename.lower()

    for suffix in (".gz", ".gzip"):
        if lower.endswith(suffix):
            filename = filename[: -len(suffix)]
            break

    filename = re.sub(r"[^\w.\-]+", "_", filename)

    return filename


def stem_from_url(url: str) -> str:
    filename = filename_from_url(url)
    lower = filename.lower()

    for suffix in (".yaml", ".yml", ".txt", ".list", ".conf", ".rule"):
        if lower.endswith(suffix):
            return filename[: -len(suffix)]

    return Path(filename).stem or filename


def unique_path(path: Path, used: set[Path]) -> Path:
    """
    同一次运行内避免多个链接生成同名文件。
    注意：已有文件允许覆盖，这样每天更新不会变成 xxx-2.mrs。
    """
    if path not in used:
        used.add(path)
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent

    i = 2

    while True:
        candidate = parent / f"{stem}-{i}{suffix}"

        if candidate not in used:
            used.add(candidate)
            return candidate

        i += 1


def download(url: str, dst: Path) -> None:
    log(f"下载: {url}")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "mihomo-mrs-auto-convert/1.0",
            "Accept": "*/*",
        },
    )

    with urllib.request.urlopen(req, timeout=90) as response:
        data = response.read()

    if url.lower().endswith((".gz", ".gzip")):
        data = gzip.decompress(data)

    dst.write_bytes(data)


def strip_inline_comment(line: str) -> str:
    # 只去掉空格后的 # 注释，避免误伤正则或特殊规则
    return line.split(" #", 1)[0].strip()


def strip_yaml_quote(line: str) -> str:
    line = line.strip()

    if len(line) >= 2 and line[0] == line[-1] and line[0] in ("'", '"'):
        return line[1:-1].strip()

    return line


def normalize_yaml_or_text_line(raw: str) -> str:
    line = raw.strip().lstrip("\ufeff")

    if not line:
        return ""

    if line.startswith("#"):
        return ""

    line = strip_inline_comment(line)

    if not line:
        return ""

    # YAML:
    # payload:
    #   - DOMAIN-SUFFIX,example.com
    #   - '192.168.0.0/16'
    if line.lower() in {"payload:", "payload: []"}:
        return ""

    if line.startswith("- "):
        line = line[2:].strip()

    line = strip_yaml_quote(line)
    line = strip_yaml_quote(line)

    return line.strip()


def is_ip_cidr(value: str) -> bool:
    value = value.strip()

    try:
        ipaddress.ip_network(value, strict=False)
        return "/" in value
    except ValueError:
        return False


def is_plain_domain(value: str) -> bool:
    value = value.strip()

    if not value:
        return False

    if " " in value or "/" in value:
        return False

    if value.startswith(("http://", "https://")):
        return False

    # mihomo domain rule-provider 常见写法
    if value.startswith(("+.", ".", "*.")):
        return True

    if "*" in value:
        return True

    if value.startswith(("full:", "domain:", "keyword:", "regexp:")):
        return True

    return bool(re.search(r"^[A-Za-z0-9_.+\-:*]+\.[A-Za-z0-9_.+\-:*]+$", value))


def convert_classical_domain(rule_type: str, value: str) -> str | None:
    rule_type = rule_type.upper()
    value = value.strip()

    if not value:
        return None

    if rule_type in {"DOMAIN", "HOST"}:
        return value

    if rule_type in {"DOMAIN-SUFFIX", "HOST-SUFFIX"}:
        value = value.lstrip(".")
        return f".{value}"

    if rule_type in {"DOMAIN-KEYWORD", "HOST-KEYWORD"}:
        return f"*{value}*"

    if rule_type == "DOMAIN-WILDCARD":
        return value

    return None


def parse_rules(path: Path) -> tuple[list[str], list[str], list[str]]:
    domains: list[str] = []
    ipcidrs: list[str] = []
    skipped: list[str] = []

    seen_domains: set[str] = set()
    seen_ipcidrs: set[str] = set()

    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = normalize_yaml_or_text_line(raw)

        if not line:
            continue

        # 兼容 Surge / Clash classical:
        # DOMAIN-SUFFIX,example.com
        # IP-CIDR,1.1.1.0/24,no-resolve
        parts = [p.strip() for p in line.split(",")]
        head = parts[0].upper() if parts else ""

        if head in DOMAIN_RULE_TYPES and len(parts) >= 2:
            item = convert_classical_domain(head, parts[1])

            if item and item not in seen_domains:
                domains.append(item)
                seen_domains.add(item)

            continue

        if head in IP_RULE_TYPES and len(parts) >= 2:
            item = parts[1]

            if is_ip_cidr(item) and item not in seen_ipcidrs:
                ipcidrs.append(item)
                seen_ipcidrs.add(item)
            else:
                skipped.append(line)

            continue

        if head in SKIP_RULE_TYPES:
            skipped.append(line)
            continue

        # 兼容部分 geosite 源格式：
        # full:example.com
        # domain:example.com
        # keyword:google
        lower = line.lower()

        if lower.startswith("full:"):
            item = line.split(":", 1)[1].strip()

            if item and item not in seen_domains:
                domains.append(item)
                seen_domains.add(item)

            continue

        if lower.startswith("domain:"):
            item = "." + line.split(":", 1)[1].strip().lstrip(".")

            if item and item not in seen_domains:
                domains.append(item)
                seen_domains.add(item)

            continue

        if lower.startswith("keyword:"):
            item = "*" + line.split(":", 1)[1].strip() + "*"

            if item and item not in seen_domains:
                domains.append(item)
                seen_domains.add(item)

            continue

        if lower.startswith("regexp:"):
            # domain behavior 不是 classical，regexp 不稳定，跳过
            skipped.append(line)
            continue

        # 纯 CIDR
        if is_ip_cidr(line):
            if line not in seen_ipcidrs:
                ipcidrs.append(line)
                seen_ipcidrs.add(line)

            continue

        # 纯域名 / wildcard
        if is_plain_domain(line):
            if line not in seen_domains:
                domains.append(line)
                seen_domains.add(line)

            continue

        skipped.append(line)

    return domains, ipcidrs, skipped


def write_text_rules(path: Path, rules: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + "\n", encoding="utf-8")


def run_convert(behavior: str, txt_file: Path, mrs_file: Path) -> None:
    tmp_file = mrs_file.with_suffix(".mrs.tmp")

    if tmp_file.exists():
        tmp_file.unlink()

    cmd = [
        MIHOMO_BIN,
        "convert-ruleset",
        behavior,
        "text",
        str(txt_file),
        str(tmp_file),
    ]

    log("执行: " + " ".join(cmd))

    subprocess.run(cmd, check=True)

    tmp_file.replace(mrs_file)

    log(f"生成: {mrs_file.relative_to(ROOT_DIR)}")


def build_one(url: str, tmpdir: Path, used_outputs: set[Path]) -> None:
    filename = filename_from_url(url)
    stem = stem_from_url(url)

    source_file = tmpdir / filename

    download(url, source_file)

    domains, ipcidrs, skipped = parse_rules(source_file)

    if skipped:
        log(f"{filename}: 跳过 {len(skipped)} 条不适合 domain/ipcidr mrs 的规则")

    outputs: list[tuple[str, list[str], str]] = []

    if domains and ipcidrs:
        outputs.append(("domain", domains, f"{stem}-domain"))
        outputs.append(("ipcidr", ipcidrs, f"{stem}-ipcidr"))
    elif domains:
        outputs.append(("domain", domains, stem))
    elif ipcidrs:
        outputs.append(("ipcidr", ipcidrs, stem))
    else:
        die(f"{filename} 没有解析到可转换的 domain/ipcidr 规则")

    for behavior, rules, out_stem in outputs:
        txt_file = unique_path(OUT_DIR / f"{out_stem}.txt", used_outputs)
        mrs_file = txt_file.with_suffix(".mrs")

        used_outputs.add(mrs_file)

        write_text_rules(txt_file, rules)

        log(f"生成: {txt_file.relative_to(ROOT_DIR)}，共 {len(rules)} 条，behavior={behavior}")

        run_convert(behavior, txt_file, mrs_file)


def main() -> None:
    mihomo_path = Path(MIHOMO_BIN)

    if not mihomo_path.exists():
        die(f"找不到 mihomo: {MIHOMO_BIN}")

    if not os.access(mihomo_path, os.X_OK):
        die(f"mihomo 没有执行权限: {MIHOMO_BIN}")

    # 不生成 manifest.json；如果旧版本残留，直接删除
    manifest = OUT_DIR / "manifest.json"

    if manifest.exists():
        manifest.unlink()

    links = read_links()
    used_outputs: set[Path] = set()

    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)

        for url in links:
            build_one(url, tmpdir, used_outputs)

    log("全部完成")


if __name__ == "__main__":
    main()
