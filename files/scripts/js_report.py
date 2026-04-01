#!/usr/bin/env python3
"""
Постобработка результатов web/recon/js → Markdown отчёт.

Читает out/ директорию скана и генерирует:
  - карту API-эндпоинтов (группировка, параметрические пути / IDOR candidates)
  - сводку semgrep (таблица по правилам)
  - найденные секреты (trufflehog)
  - highlights из кастомного regex-сканера
  - автоматические приоритеты для ручной проверки

Использование:
  python3 js_report.py <scan_dir> [-o output.md]
  <scan_dir> — директория, созданная web/recon/js (напр. ./app.lava.top.https)
"""
import os
import re
import sys
import json
import argparse
from datetime import date
from collections import defaultdict, Counter

# Шумовые префиксы и расширения, не интересные при анализе
NOISE_PREFIXES = [
    "/%3E", "/a/b", "/a/i", "../../", "http", "/ROOT/",
    "/SENTRY", "/AUTHOR", "_next/", "static/chunks/",
]
STATIC_EXTS = (
    ".js", ".css", ".json", ".png", ".jpg", ".jpeg",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".txt", ".pdf",
)

# Префиксы, характерные для API (выделяем отдельным блоком)
API_PREFIXES = (
    "/api/", "/aa/", "/uss/", "/rsk/", "/admin/", "/internal/",
    "/v1/", "/v2/", "/v3/", "/graphql", "/gql",
)

# Паттерны → человекочитаемые приоритеты (ищем в regex-hits.txt по имени категории)
PRIORITY_MAP = {
    "HARDCODED_CRED":          "**Hardcoded credentials** — учётные данные в коде",
    "AWS_KEY":                 "**AWS Key** — AKIA* ключ в коде, проверить валидность",
    "PRIVATE_KEY":             "**Private key** — приватный ключ в коде",
    "POSTMESSAGE_OPEN_REDIRECT": "**postMessage Open Redirect** — `location = e.data.*` без проверки `event.origin`",
    "POSTMESSAGE_WILDCARD":    "**postMessage wildcard** — отправка данных с `targetOrigin='*'`",
    "ADMIN_ROLE_CHECK":        "**Client-side auth** — формат и логика admin-роли видны в JS",
    "SENTRY_DSN":              "**Sentry DSN** — раскрыт в JS (версия релиза, окружение, self-hosted хост)",
    "EVAL_USAGE":              "**eval()** — потенциальный XSS sink, трассировать источник",
    "INNER_HTML":              "**innerHTML** — присвоение переменной, проверить источник данных",
    "OPEN_REDIRECT_SINK":      "**Open Redirect** — `location` присваивается переменная, проверить источник",
    "PROTOTYPE_POLLUTION":     "**Prototype Pollution** — потенциальная точка, проверить merge/assign",
    "JWT_TOKEN":               "**JWT токен** — хардкодом в JS, проверить актуальность",
    "CORS_WILDCARD":           "**CORS wildcard** — `Access-Control-Allow-Origin: *` в коде",
}


def is_noise(url: str) -> bool:
    if len(url) < 3:
        return True
    for p in NOISE_PREFIXES:
        if url.startswith(p):
            return True
    if any(url.endswith(e) for e in STATIC_EXTS):
        return True
    return False


def parse_endpoints(filepath: str):
    if not os.path.isfile(filepath):
        return []
    seen = set()
    endpoints = []
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            url = d.get("url", "").strip()
            if not url or is_noise(url):
                continue
            if url in seen:
                continue
            seen.add(url)
            endpoints.append({
                "url": url,
                "method": d.get("method", ""),
                "qp": d.get("queryParams", []),
                "bp": d.get("bodyParams", []),
            })
    return endpoints


def parse_semgrep(filepath: str):
    if not os.path.isfile(filepath):
        return []
    try:
        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("results", [])
    except Exception:
        return []


def parse_secrets(filepath: str):
    if not os.path.isfile(filepath):
        return []
    secrets = []
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    secrets.append(json.loads(line))
                except Exception:
                    pass
    except Exception:
        pass
    return secrets


def read_file(filepath: str) -> str:
    if not os.path.isfile(filepath):
        return ""
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def generate_report(scandir: str) -> str:
    outdir = os.path.join(scandir, "out")
    lines = []
    add = lines.append

    target_name = os.path.basename(scandir.rstrip("/\\"))

    # ── Header ────────────────────────────────────────────────────────────
    add(f"# JS Recon Report — {target_name}")
    add(f"\n**Дата**: {date.today()}  ")
    add(f"**Директория**: `{os.path.realpath(scandir)}`\n")
    add("---\n")

    # ── Endpoints ─────────────────────────────────────────────────────────
    endpoints = parse_endpoints(os.path.join(outdir, "endpoints.txt"))
    parametric = [e for e in endpoints if e["qp"] or e["bp"]]
    api_eps = [e for e in endpoints if any(e["url"].startswith(p) for p in API_PREFIXES)]
    other_eps = [e for e in endpoints if not any(e["url"].startswith(p) for p in API_PREFIXES)]

    add("## Эндпоинты\n")

    if not endpoints:
        add("Файл `out/endpoints.txt` не найден или пуст. Запустите `--item 1` (jsluice).\n")
    else:
        add(f"Всего уникальных: **{len(endpoints)}** | API: **{len(api_eps)}** | С параметрами: **{len(parametric)}**\n")

        # API endpoints grouped by namespace
        if api_eps:
            add("### API-эндпоинты\n")
            by_ns = defaultdict(list)
            for ep in api_eps:
                ns = ep["url"].lstrip("/").split("/")[0]
                by_ns[ns].append(ep)

            for ns in sorted(by_ns.keys()):
                add(f"**`/{ns}/`**\n")
                seen_u = set()
                for ep in sorted(by_ns[ns], key=lambda x: x["url"]):
                    if ep["url"] in seen_u:
                        continue
                    seen_u.add(ep["url"])
                    m = ep["method"] or "GET?"
                    extra = ""
                    if ep["qp"]:
                        extra += f" `?{'&'.join(ep['qp'])}`"
                    if ep["bp"]:
                        extra += f" body:`{'&'.join(ep['bp'])}`"
                    add(f"- `{m}` `{ep['url']}`{extra}")
                add("")

        # Parametric endpoints — IDOR candidates
        if parametric:
            add("### Параметрические пути (IDOR candidates)\n")
            add("| URL | Query params | Body params |")
            add("|-----|-------------|-------------|")
            seen_u = set()
            for ep in sorted(parametric, key=lambda x: x["url"]):
                if ep["url"] in seen_u:
                    continue
                seen_u.add(ep["url"])
                qp = ", ".join(f"`{p}`" for p in ep["qp"]) if ep["qp"] else "—"
                bp = ", ".join(f"`{p}`" for p in ep["bp"]) if ep["bp"] else "—"
                add(f"| `{ep['url']}` | {qp} | {bp} |")
            add("")

        # Other paths — collapsed
        if other_eps:
            add("<details><summary>Прочие пути (развернуть)</summary>\n")
            add("```")
            seen_u = set()
            for ep in sorted(other_eps, key=lambda x: x["url"]):
                if ep["url"] in seen_u:
                    continue
                seen_u.add(ep["url"])
                add(ep["url"])
            add("```\n</details>\n")

    # ── Semgrep ───────────────────────────────────────────────────────────
    semgrep_results = parse_semgrep(os.path.join(outdir, "patterns.json"))
    add("## Semgrep\n")

    if not semgrep_results:
        add("Нет результатов или файл не найден. Запустите `--item 4` (semgrep).\n")
    else:
        by_rule = defaultdict(list)
        for r in semgrep_results:
            rule = r.get("check_id", "?").split(".")[-1]
            by_rule[rule].append(r)

        add(f"Всего: **{len(semgrep_results)}** срабатываний в **{len(by_rule)}** правилах\n")
        add("| Правило | Кол-во | Severity |")
        add("|---------|--------|----------|")
        for rule, items in sorted(by_rule.items(), key=lambda x: -len(x[1])):
            sev = items[0].get("extra", {}).get("severity", "?")
            add(f"| `{rule}` | {len(items)} | {sev} |")
        add("")

        add("<details><summary>Детали по файлам (развернуть)</summary>\n")
        for rule, items in sorted(by_rule.items(), key=lambda x: -len(x[1])):
            add(f"**`{rule}`**\n")
            msg = items[0].get("extra", {}).get("message", "")
            if msg:
                add(f"*{msg[:120]}*\n")
            for r in items[:15]:
                path = r.get("path", "?")
                line = r.get("start", {}).get("line", "?")
                add(f"- `{path}:{line}`")
            if len(items) > 15:
                add(f"- *...ещё {len(items) - 15}*")
            add("")
        add("</details>\n")

    # ── Secrets ───────────────────────────────────────────────────────────
    secrets = parse_secrets(os.path.join(outdir, "secrets.json"))
    add("## Trufflehog — Секреты\n")

    if not secrets:
        add("Секретов не найдено. (Если item 2 ещё не запускался — запустите `--item 2`)\n")
    else:
        by_det = Counter(s.get("DetectorName", "?") for s in secrets)
        add(f"Найдено: **{len(secrets)}**\n")
        add("| Детектор | Кол-во |")
        add("|----------|--------|")
        for det, cnt in by_det.most_common():
            add(f"| `{det}` | {cnt} |")
        add("")
        add("<details><summary>Детали (развернуть)</summary>\n")
        for s in secrets[:30]:
            det = s.get("DetectorName", "?")
            raw = str(s.get("Raw", ""))[:80]
            src = s.get("SourceMetadata", {}).get("Data", {})
            finfo = ""
            if "Filesystem" in src:
                finfo = f" ({src['Filesystem'].get('file', '')})"
            add(f"- **{det}**: `{raw}`{finfo}")
        if len(secrets) > 30:
            add(f"- *...ещё {len(secrets) - 30}*")
        add("\n</details>\n")

    # ── Custom regex ──────────────────────────────────────────────────────
    regex_content = read_file(os.path.join(outdir, "regex-hits.txt"))
    add("## Custom Regex Scan\n")

    if not regex_content.strip() or "No findings." in regex_content:
        add("Нет результатов. (Если item 5 ещё не запускался — запустите `--item 5`)\n")
    else:
        rlines = regex_content.strip().split("\n")
        add("```")
        for l in rlines[:100]:
            add(l)
        if len(rlines) > 100:
            add(f"... ещё {len(rlines) - 100} строк (полный вывод в out/regex-hits.txt)")
        add("```\n")

    # ── Priorities ────────────────────────────────────────────────────────
    add("## Приоритеты для ручной проверки\n")

    tips = []

    # Из regex-hits.txt — смотрим на имена категорий
    found_cats = set(re.findall(r"\[([A-Z_]+)\]", regex_content))
    for cat, tip in PRIORITY_MAP.items():
        if cat in found_cats:
            tips.append(tip)

    # Из semgrep
    semgrep_rules = {r.get("check_id", "").split(".")[-1].lower() for r in semgrep_results}
    if any("postmessage" in r for r in semgrep_rules):
        tip = "**postMessage (semgrep)** — wildcard `*` или небезопасная конфигурация"
        if tip not in tips:
            tips.append(tip)
    if any("open" in r and "redirect" in r for r in semgrep_rules):
        tip = "**Open Redirect (semgrep)** — обнаружен потенциальный редирект"
        if tip not in tips:
            tips.append(tip)

    # Из parametric endpoints
    if parametric:
        tips.append(
            f"**IDOR** — {len(parametric)} параметрических эндпоинтов, "
            "проверить доступ к объектам других пользователей"
        )

    # Из trufflehog
    if secrets:
        tips.append(
            f"**Секреты (trufflehog)** — {len(secrets)} находок, "
            "проверить ротацию/инвалидацию"
        )

    if tips:
        for t in tips:
            add(f"- {t}")
    else:
        add("- Ручная проверка эндпоинтов из раздела выше")
    add("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate Markdown report from web/recon/js scan directory"
    )
    parser.add_argument(
        "scandir",
        help="Scan directory created by web/recon/js (e.g. ./app.lava.top.https)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: <scandir>/out/report.md)",
    )
    args = parser.parse_args()

    if not os.path.isdir(args.scandir):
        print(f"Error: not a directory: {args.scandir}", file=sys.stderr)
        sys.exit(1)

    report = generate_report(args.scandir)
    print(report)

    outfile = args.output or os.path.join(args.scandir, "out", "report.md")
    os.makedirs(os.path.dirname(os.path.realpath(outfile)), exist_ok=True)
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"\nReport saved: {outfile}", file=sys.stderr)


if __name__ == "__main__":
    main()
