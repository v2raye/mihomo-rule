# mihomo-mrs-auto-v2

把远程 `txt` / `list` / `yaml` 规则集自动转换成 Mihomo 的 `.mrs` 文件，并输出到 `rule/mihomo/`。

支持：

- `domain`
- `ipcidr`
- `mixed`（一个源里同时有域名和 CIDR，自动拆成两个 `.mrs`）
- GitHub Actions 每天自动更新
- 有变化时自动提交到仓库

## 目录结构

```text
mihomo-mrs-auto-v2/
├── .github/
│   └── workflows/
│       └── update-rules.yml
├── rule/
│   └── mihomo/
├── scripts/
│   └── build_rules.py
├── links.txt
├── requirements.txt
└── README.md
```

## links.txt 格式

每行一条：

```text
名称|mode|format|url
```

示例：

```text
ads|domain|txt|https://example.com/ads.txt
private_ip|ipcidr|list|https://example.com/private.list
mixed_rules|mixed|yaml|https://example.com/mixed.yaml
```

字段说明：

- `名称`：输出文件名，不带扩展名
- `mode`：`domain` / `ipcidr` / `mixed`
- `format`：`txt` / `list` / `text` / `yaml` / `yml`
- `url`：远程规则地址

## mixed 模式

如果一个链接里同时有域名规则和 CIDR 规则，填 `mixed`。

例如：

```text
apple_mix|mixed|yaml|https://example.com/apple.yaml
```

脚本会自动输出：

```text
rule/mihomo/apple_mix_domain.mrs
rule/mihomo/apple_mix_ipcidr.mrs
```

### mixed 目前可识别的内容

- 纯域名：`example.com`、`.example.com`
- 纯 CIDR：`1.1.1.0/24`、`2400:3200::/32`
- `DOMAIN,example.com`
- `DOMAIN-SUFFIX,example.com`
- `IP-CIDR,1.1.1.0/24`
- `IP-CIDR6,2400:3200::/32`

### mixed 不会进入 `.mrs` 的内容

这类 classical 规则会跳过，并在日志里提示：

- `DOMAIN-KEYWORD,...`
- `GEOIP,...`
- `SRC-IP-CIDR,...`
- `DST-PORT,...`
- 其他非 `domain/ipcidr` 规则

## 本地运行

前提：系统里能直接执行 `mihomo`。

```bash
python3 -m pip install -r requirements.txt
python3 scripts/build_rules.py
```

## GitHub Actions

工作流默认按 **北京时间每天 06:00** 运行。

由于 GitHub Actions 的 `cron` 以 UTC 计算，仓库里写的是：

- `0 22 * * *`（UTC）
- 等于北京时间每天 `06:00`

也支持手动触发。

## 输出目录

所有生成文件都放在：

```text
rule/mihomo/
```

## 建议

如果你的某个源本身就是混合规则，就直接写 `mixed`，不要强行写成 `domain` 或 `ipcidr`。
