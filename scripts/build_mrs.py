#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Download txt/yaml/list rule sets, normalize them, and convert them to mihomo .mrs.

links.txt format:
  URL
  URL|output_name
  URL|output_name|behavior

behavior:
  auto    -> split domain/ipcidr automatically when needed
  domain  -> only build domain mrs
  ipcidr  -> only build ipcidr mrs
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, unquote

import requests
import yaml


ROOT = Path(__file__).resolve().parents[1]
LINKS_FILE = ROOT / "links.txt"
OUT_DIR = ROOT / "rule" / "mihomo"
BUILD_DIR = ROOT / "build"
MIHOMO_BIN = Path(os.environ.get("MIHOMO_BIN", ROOT / "bin" / "mihomo"))

TIMEOUT = int(os.environ.get("DOWNLOAD_TIMEOUT", "45"))
USER_AGENT = os.environ.get(
    "DOWNLOAD_USER_AGENT",
    "mihomo-mrs-auto-convert/1.0 (+https://github.com/)",
)

RULE_PREFIXES_DOMAIN = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-REGEX",
    "GEOSITE",
    "PROCESS-NAME",
    "PROCESS-PATH",
}
RULE_PREFIXES_IP = {
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP",
    "SRC-IP-CIDR",
    "SRC-IP-ASN",
}


@dataclass(frozen=True)
class SourceItem:
    url: str
    name: str
    behavior: str = "auto"


def die(msg: str, code: int = 1) -> None:
    print(f"[ERROR] {msg}", file=sys.stderr)
    raise SystemExit(code)


def safe_name(value: str) -> str:
    value = unquote(value).strip()
    value = re.sub(r"[?#].*$", "", value)
    value = value.rsplit("/", 1)[-1] or "ruleset"
    value = re.sub(r"\.(ya?ml|txt|list|conf|rules?)$", "", value, flags=re.I)
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-_")
    return value or "ruleset"


def parse_links(path: Path) -> list[SourceItem]:
    if not path.exists():
        die("links.txt 不存在，请先创建并写入规则链接。")

    items: list[SourceItem] = []
    used: dict[str, int] = {}

    for idx, raw in enumerate(path.read_text("utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split("|")]
        url = parts[0]
        if not re.match(r"^https?://", url, flags=re.I):
            print(f"[WARN] links.txt 第 {idx} 行不是 http/https 链接，已跳过：{line}")
            continue

        name = parts[1] if len(parts) >= 2 and parts[1] else safe_name(urlparse(url).path)
        name = safe_name(name)

        behavior = parts[2].lower() if len(parts) >= 3 and parts[2] else "auto"
        if behavior not in {"auto", "domain", "ipcidr"}:
            print(f"[WARN] links.txt 第 {idx} 行 behavior 无效，改为 auto：{behavior}")
            behavior = "auto"

        base = name
        used[base] = used.get(base, 0) + 1
        if used[base] > 1:
            name = f"{base}-{used[base]}"

        items.append(SourceItem(url=url, name=name, behavior=behavior))

    if not items:
        die("links.txt 没有有效链接。")
    return items


def download(url: str) -> str:
    print(f"[INFO] Download: {url}")
    resp = requests.get(
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=TIMEOUT,
        allow_redirects=True,
    )
    resp.raise_for_status()
    resp.encoding = resp.encoding or "utf-8"
    return resp.text


def strip_inline_comment(line: str) -> str:
    # Do not treat "http://", "https://", or AdGuard "##" as comments.
    for marker in (" #", "\t#", " //", "\t//"):
        pos = line.find(marker)
        if pos >= 0:
            return line[:pos].strip()
    return line.strip()


def extract_yaml_payload(text: str) -> tuple[list[str], str | None]:
    try:
        data = yaml.safe_load(text)
    except Exception:
        return [], None

    if data is None:
        return [], None

    if isinstance(data, dict):
        behavior = data.get("behavior")
        payload = data.get("payload")
        if isinstance(payload, list):
            return [str(x).strip() for x in payload if str(x).strip()], (
                str(behavior).lower() if behavior else None
            )

        # Some files are complete provider maps: name: {payload: [...]}
        collected: list[str] = []
        detected_behavior: str | None = None
        for value in data.values():
            if isinstance(value, dict) and isinstance(value.get("payload"), list):
                collected.extend(str(x).strip() for x in value["payload"] if str(x).strip())
                if not detected_behavior and value.get("behavior"):
                    detected_behavior = str(value["behavior"]).lower()
        if collected:
            return collected, detected_behavior

    if isinstance(data, list):
        return [str(x).strip() for x in data if str(x).strip()], None

    return [], None


def is_ip_or_cidr(value: str) -> str | None:
    value = value.strip().strip("'\"")
    if not value:
        return None

    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            return str(net)
        ip = ipaddress.ip_address(value)
        return f"{ip}/32" if ip.version == 4 else f"{ip}/128"
    except ValueError:
        return None


def normalize_domain(value: str) -> str | None:
    v = value.strip().strip("'\"").lower().rstrip(".")
    if not v:
        return None

    # AdGuard style: ||example.com^
    if v.startswith("@@"):
        return None
    if v.startswith("||"):
        v = v[2:]
        v = re.split(r"[\^/$]", v, 1)[0].strip(".")
        if v:
            return f"+.{v}"

    # hosts style: 0.0.0.0 example.com or ::1 example.com
    parts = v.split()
    if len(parts) >= 2 and is_ip_or_cidr(parts[0]):
        v = parts[1].strip().rstrip(".")

    # Wildcard domain.
    if v.startswith("*."):
        v = "+." + v[2:]

    if v.startswith("."):
        v = "+." + v[1:]

    # Drop obvious unsupported rule syntaxes.
    if any(ch in v for ch in ("/", "\\", ":", "@", "[", "]")):
        return None
    if v.startswith(("regexp:", "keyword:", "full:")):
        return None

    # '+.example.com' or 'example.com'
    candidate = v[2:] if v.startswith("+.") else v
    labels = candidate.split(".")
    if len(labels) < 2:
        return None
    if not all(re.fullmatch(r"[a-z0-9-]{1,63}", label) for label in labels):
        return None
    if labels[-1].isdigit():
        return None
    return v


def parse_rule_line(line: str) -> tuple[str | None, str | None]:
    """
    Return (kind, value)
      kind: domain / ipcidr / None
    """
    line = strip_inline_comment(line.strip())
    if not line:
        return None, None

    # Remove YAML list marker.
    if line.startswith("- "):
        line = line[2:].strip()

    line = line.strip().strip("'\"")
    if not line:
        return None, None

    # Drop comments / headers / unsupported AdGuard cosmetic rules.
    low = line.lower()
    if (
        line.startswith(("#", ";", "//", "["))
        or "##" in line
        or "#@#" in line
        or low.startswith(("payload:", "rules:", "rule-providers:", "behavior:", "format:"))
    ):
        return None, None

    # Clash/Mihomo classical rule line.
    # DOMAIN-SUFFIX,example.com,PROXY
    if "," in line:
        fields = [x.strip().strip("'\"") for x in line.split(",")]
        key = fields[0].upper()
        if key in RULE_PREFIXES_DOMAIN and len(fields) >= 2:
            if key == "DOMAIN":
                domain = normalize_domain(fields[1])
            elif key == "DOMAIN-SUFFIX":
                d = normalize_domain(fields[1])
                domain = f"+.{d[2:] if d and d.startswith('+.') else d}" if d else None
            else:
                # DOMAIN-KEYWORD / DOMAIN-REGEX / GEOSITE / process rules are not mrs-domain payload.
                domain = None
            return ("domain", domain) if domain else (None, None)

        if key in RULE_PREFIXES_IP and len(fields) >= 2:
            cidr = is_ip_or_cidr(fields[1])
            return ("ipcidr", cidr) if cidr else (None, None)

    cidr = is_ip_or_cidr(line)
    if cidr:
        return "ipcidr", cidr

    domain = normalize_domain(line)
    if domain:
        return "domain", domain

    return None, None


def unique_sorted(values: list[str]) -> list[str]:
    seen = set()
    out = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return sorted(out)


def collect_rules(text: str) -> tuple[list[str], list[str], str | None]:
    payload, yaml_behavior = extract_yaml_payload(text)
    lines = payload if payload else text.splitlines()

    domains: list[str] = []
    cidrs: list[str] = []

    for raw in lines:
        kind, value = parse_rule_line(str(raw))
        if kind == "domain" and value:
            domains.append(value)
        elif kind == "ipcidr" and value:
            cidrs.append(value)

    return unique_sorted(domains), unique_sorted(cidrs), yaml_behavior


def write_text_rules(path: Path, payload: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(payload) + "\n", encoding="utf-8")


def convert_with_mihomo(behavior: str, src: Path, dst: Path) -> None:
    cmd = [str(MIHOMO_BIN), "convert-ruleset", behavior, "text", str(src), str(dst)]
    print("[INFO] Run:", " ".join(cmd))
    subprocess.run(cmd, cwd=str(ROOT), check=True)


def clean_output() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    for pattern in ("*.mrs", "*.json"):
        for p in OUT_DIR.glob(pattern):
            p.unlink()


def main() -> int:
    if not MIHOMO_BIN.exists():
        die(f"找不到 mihomo 可执行文件：{MIHOMO_BIN}")

    items = parse_links(LINKS_FILE)
    clean_output()

    manifest: dict[str, object] = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "items": [],
    }

    with tempfile.TemporaryDirectory(prefix="mrs-build-") as td:
        tmp = Path(td)

        for item in items:
            entry: dict[str, object] = {
                "url": item.url,
                "name": item.name,
                "behavior": item.behavior,
                "outputs": [],
                "skipped": [],
            }

            try:
                text = download(item.url)
                domains, cidrs, yaml_behavior = collect_rules(text)

                # If links.txt says auto and the YAML declares behavior, honor it unless unsupported.
                wanted = item.behavior
                if wanted == "auto" and yaml_behavior in {"domain", "ipcidr"}:
                    wanted = yaml_behavior

                jobs: list[tuple[str, list[str], str]]
                if wanted == "domain":
                    jobs = [("domain", domains, f"{item.name}.mrs")]
                elif wanted == "ipcidr":
                    jobs = [("ipcidr", cidrs, f"{item.name}.mrs")]
                else:
                    jobs = []
                    if domains:
                        suffix = "-domain" if cidrs else ""
                        jobs.append(("domain", domains, f"{item.name}{suffix}.mrs"))
                    if cidrs:
                        suffix = "-ipcidr" if domains else ""
                        jobs.append(("ipcidr", cidrs, f"{item.name}{suffix}.mrs"))

                if not jobs:
                    entry["skipped"] = ["no supported domain/ipcidr payload detected"]
                    print(f"[WARN] {item.name}: 没有检测到可转换的 domain/ipcidr 规则")
                else:
                    for behavior, payload, out_name in jobs:
                        if not payload:
                            entry["skipped"].append(f"{behavior}: empty")
                            continue

                        src = tmp / f"{item.name}-{behavior}.txt"
                        dst = OUT_DIR / out_name
                        write_text_rules(src, payload)
                        convert_with_mihomo(behavior, src, dst)

                        entry["outputs"].append(
                            {
                                "file": str(dst.relative_to(ROOT)).replace("\\", "/"),
                                "behavior": behavior,
                                "count": len(payload),
                            }
                        )

            except Exception as exc:
                entry["error"] = str(exc)
                print(f"[ERROR] {item.name}: {exc}", file=sys.stderr)

            manifest["items"].append(entry)

    (OUT_DIR / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    errors = [x for x in manifest["items"] if isinstance(x, dict) and x.get("error")]
    if errors:
        print(f"[WARN] 有 {len(errors)} 个源转换失败，其他源已继续处理。")
        # Return 0 so one failed upstream URL does not block all successful output.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
