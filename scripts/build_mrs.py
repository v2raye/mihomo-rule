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


# 可以安全转换进 mihomo behavior=domain 的 classical 规则
DOMAIN_RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "HOST",
    "HOST-SUFFIX",
    "HOST-KEYWORD",
}


# 只转换目标 IP CIDR。
# SRC-IP-CIDR 是源地址匹配，不能混进普通 ipcidr.mrs。
IP_RULE_TYPES = {
    "IP-CIDR",
    "IP-CIDR6",
}


# 这些规则无法完整表达为 mrs domain/ipcidr，统一跳过
SKIP_RULE_TYPES = {
    "GEOIP",
    "GEOSITE",
    "IP-ASN",
    "SRC-GEOIP",
    "SRC-IP-ASN",
    "SRC-IP-CIDR",
    "SRC-IP-CIDR6",
    "SRC-IP-SUFFIX",
    "IP-SUFFIX",
    "DOMAIN-REGEX",
    "URL-REGEX",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "PROCESS-PATH-WILDCARD",
    "PROCESS-PATH-REGEX",
    "PROCESS-NAME-WILDCARD",
    "PROCESS-NAME-REGEX",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "IN-TYPE",
    "IN-USER",
    "IN-NAME",
    "NETWORK",
    "UID",
    "DSCP",
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
        # https://example.com/private.yaml # comment
        line = line.split(" #", 1)[0].strip()

        # 兼容旧写法：
        # https://example.com/private.yaml|private|ipcidr
        # 现在只取链接本体，输出名统一从 URL 文件名自动识别
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

    # 防止 URL 文件名里有不适合作为文件名的字符
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
    已存在的同名文件允许覆盖，这样每天更新不会变成 xxx-2.mrs。
    """
    if path not in used:
        used.add(path)
        return path

    stem = path.stem
    suffix = path.suffix
    parent = path.parent

    index = 2

    while True:
        candidate = parent / f"{stem}-{index}{suffix}"

        if candidate not in used:
            used.add(candidate)
            return candidate

        index += 1


def clean_output_dir() -> None:
    """
    每次重新生成，避免 links.txt 删除链接后旧文件残留。
    只清理本项目自动生成的 .mrs / .txt / .tmp / manifest.json。
    """
    for pattern in ("*.mrs", "*.txt", "*.tmp", "manifest.json"):
        for old_file in OUT_DIR.glob(pattern):
            if old_file.is_file():
                old_file.unlink()
                log(f"删除旧文件: {old_file.relative_to(ROOT_DIR)}")


def download(url: str, dst: Path) -> None:
    log(f"下载: {url}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "mihomo-mrs-auto-convert/1.0",
            "Accept": "*/*",
        },
    )

    with urllib.request.urlopen(request, timeout=90) as response:
        data = response.read()

    if url.lower().endswith((".gz", ".gzip")):
        data = gzip.decompress(data)

    dst.write_bytes(data)


def strip_inline_comment(line: str) -> str:
    # 只去掉空格后的 # 注释，避免误伤正则、通配符或特殊规则
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

    if line.startswith(("#", ";", "!", "//")):
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


def is_ip_address(value: str) -> bool:
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def is_domain_provider_item(value: str) -> bool:
    """
    mihomo domain provider 文本规则：
    - example.com
    - .example.com
    - *.example.com
    - *.*.example.com
    - *keyword*
    这里做基础合法性过滤，真正语法由 mihomo convert-ruleset 再校验。
    """
    value = value.strip()

    if not value:
        return False

    if "," in value or " " in value or "\t" in value or "/" in value:
        return False

    if value.startswith(("http://", "https://")):
        return False

    if is_ip_address(value):
        return False

    # 兼容部分 Clash 规则源里的 +.example.com
    if value.startswith("+."):
        return bool(re.search(r"[A-Za-z0-9-]+\.[A-Za-z0-9.-]+$", value[2:]))

    # 后缀写法：.example.com
    if value.startswith("."):
        return bool(re.search(r"[A-Za-z0-9-]+\.[A-Za-z0-9.-]+$", value[1:]))

    # wildcard / keyword 近似写法
    if "*" in value:
        return bool(re.search(r"[A-Za-z0-9]", value)) and bool(
            re.fullmatch(r"[A-Za-z0-9*_.+\-]+", value)
        )

    # 普通完整域名
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.\-]*\.[A-Za-z0-9_.\-]+", value))


def convert_classical_domain(rule_type: str, value: str) -> str | None:
    rule_type = rule_type.upper()
    value = value.strip()

    if not value:
        return None

    if rule_type in {"DOMAIN", "HOST"}:
        item = value

    elif rule_type in {"DOMAIN-SUFFIX", "HOST-SUFFIX"}:
        value = value.lstrip(".")
        item = f".{value}"

    elif rule_type in {"DOMAIN-KEYWORD", "HOST-KEYWORD"}:
        # 近似转换：DOMAIN-KEYWORD,google -> *google*
        # mihomo domain provider 使用 Clash wildcard。
        # 这不是 classical 的 100% 等价，但比直接丢弃更适合自动转换场景。
        if any(ch in value for ch in (" ", ",", "/", "\\")):
            return None
        item = f"*{value}*"

    elif rule_type == "DOMAIN-WILDCARD":
        item = value

    else:
        return None

    if is_domain_provider_item(item):
        return item

    return None


def convert_geosite_like_line(line: str) -> str | None:
    """
    兼容部分 geosite 源格式：
    full:example.com
    domain:example.com
    keyword:google
    """
    lower = line.lower()

    if lower.startswith("full:"):
        item = line.split(":", 1)[1].strip()

    elif lower.startswith("domain:"):
        item = "." + line.split(":", 1)[1].strip().lstrip(".")

    elif lower.startswith("keyword:"):
        keyword = line.split(":", 1)[1].strip()

        if any(ch in keyword for ch in (" ", ",", "/", "\\")):
            return None

        item = f"*{keyword}*"

    elif lower.startswith("regexp:"):
        return None

    else:
        return None

    if is_domain_provider_item(item):
        return item

    return None


def convert_adblock_like_line(line: str) -> str | None:
    """
    简单兼容 AdGuard / ABP 域名锚定规则：
    ||example.com^ -> .example.com

    只转换最常见、可安全映射的域名锚定形式；
    复杂 cosmetic / regex / allowlist 规则全部跳过。
    """
    if line.startswith("@@"):
        return None

    if not line.startswith("||"):
        return None

    body = line[2:]

    # 去掉 ABP 结尾锚点和参数
    body = body.split("^", 1)[0]
    body = body.split("$", 1)[0]
    body = body.strip()

    if not body:
        return None

    if body.startswith("*") or "/" in body or ":" in body:
        return None

    item = "." + body.lstrip(".")

    if is_domain_provider_item(item):
        return item

    return None


def convert_hosts_line(line: str) -> str | None:
    """
    兼容 hosts 格式：
    0.0.0.0 example.com
    127.0.0.1 example.com
    """
    parts = line.split()

    if len(parts) < 2:
        return None

    first = parts[0].strip()
    second = parts[1].strip()

    if not is_ip_address(first):
        return None

    if is_domain_provider_item(second):
        return second

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

        # 兼容 Surge / Clash classical：
        # DOMAIN-SUFFIX,example.com
        # IP-CIDR,1.1.1.0/24,no-resolve
        parts = [p.strip() for p in line.split(",")]
        head = parts[0].upper() if parts else ""

        if head in DOMAIN_RULE_TYPES and len(parts) >= 2:
            item = convert_classical_domain(head, parts[1])

            if item and item not in seen_domains:
                domains.append(item)
                seen_domains.add(item)
            elif not item:
                skipped.append(line)

            continue

        if head in IP_RULE_TYPES and len(parts) >= 2:
            item = parts[1].strip()

            if is_ip_cidr(item) and item not in seen_ipcidrs:
                ipcidrs.append(item)
                seen_ipcidrs.add(item)
            else:
                skipped.append(line)

            continue

        if head in SKIP_RULE_TYPES:
            skipped.append(line)
            continue

        # 兼容：192.168.0.0/16,no-resolve
        if len(parts) >= 2 and is_ip_cidr(parts[0]):
            item = parts[0]

            if item not in seen_ipcidrs:
                ipcidrs.append(item)
                seen_ipcidrs.add(item)

            continue

        # 兼容 geosite-like 行
        geosite_item = convert_geosite_like_line(line)

        if geosite_item:
            if geosite_item not in seen_domains:
                domains.append(geosite_item)
                seen_domains.add(geosite_item)

            continue

        # 兼容 AdGuard / ABP 简单域名规则
        adblock_item = convert_adblock_like_line(line)

        if adblock_item:
            if adblock_item not in seen_domains:
                domains.append(adblock_item)
                seen_domains.add(adblock_item)

            continue

        # 兼容 hosts
        hosts_item = convert_hosts_line(line)

        if hosts_item:
            if hosts_item not in seen_domains:
                domains.append(hosts_item)
                seen_domains.add(hosts_item)

            continue

        # 纯 CIDR
        if is_ip_cidr(line):
            if line not in seen_ipcidrs:
                ipcidrs.append(line)
                seen_ipcidrs.add(line)

            continue

        # 纯 domain provider item
        if is_domain_provider_item(line):
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

    log(
        f"{filename}: domain={len(domains)}, ipcidr={len(ipcidrs)}, skipped={len(skipped)}"
    )

    if skipped:
        log(f"{filename}: 已跳过 {len(skipped)} 条无法转换为 domain/ipcidr mrs 的规则")

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

    clean_output_dir()

    links = read_links()
    used_outputs: set[Path] = set()

    with tempfile.TemporaryDirectory() as td:
        tmpdir = Path(td)

        for url in links:
            build_one(url, tmpdir, used_outputs)

    log("全部完成")


if __name__ == "__main__":
    main()
