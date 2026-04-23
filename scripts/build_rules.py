#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import ipaddress
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

import requests
import yaml

ROOT = Path(__file__).resolve().parent.parent
LINKS_FILE = ROOT / "links.txt"
OUTPUT_DIR = ROOT / "rule" / "mihomo"
USER_AGENT = "mihomo-mrs-auto/2.0"
TIMEOUT = 60
SUPPORTED_FORMATS = {"txt", "list", "text", "yaml", "yml"}
SUPPORTED_MODES = {"domain", "ipcidr", "mixed"}


@dataclass
class RuleItem:
    name: str
    mode: str
    fmt: str
    url: str

    @property
    def input_fmt(self) -> str:
        fmt = self.fmt.lower().strip()
        if fmt in {"txt", "list", "text"}:
            return "text"
        if fmt in {"yaml", "yml"}:
            return "yaml"
        raise ValueError(f"不支持的 format: {self.fmt}")


@dataclass
class SplitResult:
    domains: List[str]
    ipcidrs: List[str]
    skipped: List[str]


def ensure_mihomo() -> str:
    path = shutil.which("mihomo")
    if not path:
        raise RuntimeError("未找到 mihomo 命令，请先安装 Mihomo。")
    return path


def parse_links(path: Path) -> List[RuleItem]:
    if not path.exists():
        raise FileNotFoundError(f"未找到配置文件: {path}")

    items: List[RuleItem] = []
    for idx, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 4:
            raise ValueError(
                f"links.txt 第 {idx} 行格式错误，应为：名称|mode|format|url\n实际内容：{raw}"
            )

        name, mode, fmt, url = parts
        mode = mode.lower()
        fmt = fmt.lower()

        if not name:
            raise ValueError(f"links.txt 第 {idx} 行名称为空")
        if mode not in SUPPORTED_MODES:
            raise ValueError(f"links.txt 第 {idx} 行 mode 只能是 domain / ipcidr / mixed")
        if fmt not in SUPPORTED_FORMATS:
            raise ValueError(f"links.txt 第 {idx} 行 format 仅支持 txt/list/text/yaml/yml")
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError(f"links.txt 第 {idx} 行 url 非法：{url}")

        items.append(RuleItem(name=name, mode=mode, fmt=fmt, url=url))

    if not items:
        print("[INFO] links.txt 中没有可处理的规则。")
    return items


def download_file(url: str, target: Path) -> None:
    headers = {"User-Agent": USER_AGENT}
    with requests.get(url, headers=headers, timeout=TIMEOUT, stream=True) as resp:
        resp.raise_for_status()
        with target.open("wb") as f:
            for chunk in resp.iter_content(chunk_size=1024 * 64):
                if chunk:
                    f.write(chunk)


def sha256sum(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def convert_rule(mihomo_bin: str, behavior: str, input_fmt: str, src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    cmd = [mihomo_bin, "convert-ruleset", behavior, input_fmt, str(src), str(dst)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"转换失败\n命令: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )


def read_source_entries(path: Path, input_fmt: str) -> List[str]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if input_fmt == "text":
        return text.splitlines()

    data = yaml.safe_load(text)
    if data is None:
        return []

    if isinstance(data, dict) and isinstance(data.get("payload"), list):
        return [str(x) for x in data["payload"]]
    if isinstance(data, list):
        return [str(x) for x in data]

    raise ValueError("YAML 内容无法识别，需为 payload 列表或顶层列表")


def strip_inline_comment(line: str) -> str:
    line = line.strip().strip("'\"")
    for sep in (" #", " ;", " //"):
        if sep in line:
            line = line.split(sep, 1)[0].strip()
    return line.strip()


def is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def looks_like_domain(value: str) -> bool:
    if not value:
        return False
    value = value.strip().lstrip(".").strip()
    if not value or " " in value or "/" in value:
        return False
    return "." in value


def normalize_domain_value(value: str) -> str:
    return value.strip().strip("'\"")


def split_mixed_entries(entries: Sequence[str]) -> SplitResult:
    domains: List[str] = []
    ipcidrs: List[str] = []
    skipped: List[str] = []
    seen_domain = set()
    seen_ipcidr = set()

    for raw in entries:
        line = strip_inline_comment(str(raw))
        if not line or line.startswith("#"):
            continue

        if "," not in line:
            if is_cidr(line):
                if line not in seen_ipcidr:
                    ipcidrs.append(line)
                    seen_ipcidr.add(line)
            elif looks_like_domain(line):
                domain = normalize_domain_value(line)
                if domain and domain not in seen_domain:
                    domains.append(domain)
                    seen_domain.add(domain)
            else:
                skipped.append(line)
            continue

        parts = [p.strip() for p in line.split(",")]
        rule_type = parts[0].upper()
        value = parts[1] if len(parts) > 1 else ""

        if rule_type in {"IP-CIDR", "IP-CIDR6"}:
            if is_cidr(value) and value not in seen_ipcidr:
                ipcidrs.append(value)
                seen_ipcidr.add(value)
            else:
                skipped.append(line)
            continue

        if rule_type == "DOMAIN":
            domain = normalize_domain_value(value)
            if looks_like_domain(domain) and domain not in seen_domain:
                domains.append(domain)
                seen_domain.add(domain)
            else:
                skipped.append(line)
            continue

        if rule_type == "DOMAIN-SUFFIX":
            domain = normalize_domain_value(value)
            if looks_like_domain(domain):
                if not domain.startswith((".", "*")):
                    domain = "." + domain
                if domain not in seen_domain:
                    domains.append(domain)
                    seen_domain.add(domain)
            else:
                skipped.append(line)
            continue

        skipped.append(line)

    return SplitResult(domains=domains, ipcidrs=ipcidrs, skipped=skipped)


def write_text_rules(path: Path, rules: Iterable[str]) -> None:
    values = list(rules)
    path.write_text(("\n".join(values) + "\n") if values else "", encoding="utf-8")


def update_hash_message(output_path: Path, old_hash: str | None) -> None:
    new_hash = sha256sum(output_path)
    if old_hash == new_hash:
        print(f"[OK] {output_path.name}: 无变化")
    else:
        print(f"[OK] {output_path.name}: 已更新")


def remove_if_exists(path: Path) -> None:
    if path.exists():
        path.unlink()
        print(f"[INFO] 已删除空产物: {path.relative_to(ROOT)}")


def process_single_behavior(mihomo_bin: str, item: RuleItem, source_path: Path, tmpdir_path: Path) -> None:
    suffix = ".yaml" if item.input_fmt == "yaml" else ".txt"
    temp_input = tmpdir_path / f"{item.name}{suffix}"
    shutil.copyfile(source_path, temp_input)

    output_path = OUTPUT_DIR / f"{item.name}.mrs"
    old_hash = sha256sum(output_path) if output_path.exists() else None

    print(f"[INFO] 转换: {item.name} ({item.mode}, {item.input_fmt}) -> {output_path.relative_to(ROOT)}")
    convert_rule(mihomo_bin, item.mode, item.input_fmt, temp_input, output_path)
    update_hash_message(output_path, old_hash)


def process_mixed_behavior(mihomo_bin: str, item: RuleItem, source_path: Path) -> None:
    entries = read_source_entries(source_path, item.input_fmt)
    split = split_mixed_entries(entries)

    if split.skipped:
        print(f"[WARN] {item.name}: 跳过 {len(split.skipped)} 条不能映射到 domain/ipcidr 的规则，例如: {split.skipped[0]}")

    domain_output = OUTPUT_DIR / f"{item.name}_domain.mrs"
    ip_output = OUTPUT_DIR / f"{item.name}_ipcidr.mrs"

    with tempfile.TemporaryDirectory(prefix=f"{item.name}-split-") as td:
        td = Path(td)

        if split.domains:
            domain_input = td / f"{item.name}_domain.txt"
            write_text_rules(domain_input, split.domains)
            old_hash = sha256sum(domain_output) if domain_output.exists() else None
            print(f"[INFO] 转换: {item.name} mixed -> {domain_output.relative_to(ROOT)} (domain {len(split.domains)} 条)")
            convert_rule(mihomo_bin, "domain", "text", domain_input, domain_output)
            update_hash_message(domain_output, old_hash)
        else:
            remove_if_exists(domain_output)
            print(f"[INFO] {item.name}: 未识别到可转换的 domain 规则")

        if split.ipcidrs:
            ip_input = td / f"{item.name}_ipcidr.txt"
            write_text_rules(ip_input, split.ipcidrs)
            old_hash = sha256sum(ip_output) if ip_output.exists() else None
            print(f"[INFO] 转换: {item.name} mixed -> {ip_output.relative_to(ROOT)} (ipcidr {len(split.ipcidrs)} 条)")
            convert_rule(mihomo_bin, "ipcidr", "text", ip_input, ip_output)
            update_hash_message(ip_output, old_hash)
        else:
            remove_if_exists(ip_output)
            print(f"[INFO] {item.name}: 未识别到可转换的 ipcidr 规则")

    if not split.domains and not split.ipcidrs:
        raise RuntimeError("未从 mixed 源中识别出任何可转换的 domain/ipcidr 规则")


def main() -> int:
    try:
        mihomo_bin = ensure_mihomo()
        items = parse_links(LINKS_FILE)
    except Exception as e:
        print(f"[FATAL] {e}", file=sys.stderr)
        return 1

    if not items:
        return 0

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    success = 0
    failed = 0

    with tempfile.TemporaryDirectory(prefix="mihomo-mrs-auto-") as tmpdir:
        tmpdir_path = Path(tmpdir)

        for item in items:
            try:
                suffix = ".yaml" if item.input_fmt == "yaml" else ".txt"
                source_path = tmpdir_path / f"{item.name}_source{suffix}"
                print(f"[INFO] 下载: {item.url}")
                download_file(item.url, source_path)

                if item.mode in {"domain", "ipcidr"}:
                    process_single_behavior(mihomo_bin, item, source_path, tmpdir_path)
                else:
                    process_mixed_behavior(mihomo_bin, item, source_path)

                success += 1
            except Exception as e:
                failed += 1
                print(f"[ERROR] {item.name}: {e}", file=sys.stderr)

    print(f"[DONE] 成功: {success}，失败: {failed}")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
