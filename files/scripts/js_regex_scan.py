#!/usr/bin/env python3
"""
Кастомные regex-проверки JS-файлов для пентеста.
Ищет: hardcoded credentials, internal IPs, JWT, base64-блобы,
       чувствительный localStorage, postMessage, GraphQL, XSS sinks,
       AWS keys, приватные ключи, source maps, open redirect sinks.
"""
import os
import re
import sys
import argparse

PATTERNS = [
    (
        "HARDCODED_CRED",
        r'(?:password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key|client[_-]?secret)\s*[:=]\s*["\'][^"\'\\]{4,}["\']',
        "Захардкоженные учётные данные",
    ),
    (
        "AWS_KEY",
        r'\bAKIA[0-9A-Z]{16}\b',
        "AWS Access Key ID",
    ),
    (
        "PRIVATE_KEY",
        r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "Приватный ключ",
    ),
    (
        "JWT_TOKEN",
        r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
        "JWT токен",
    ),
    (
        "INTERNAL_IP",
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b',
        "Внутренние IP-адреса",
    ),
    (
        "BASE64_BLOB",
        r'["\']([A-Za-z0-9+/]{60,}={0,2})["\']',
        "Крупные base64-блобы (возможно зашифрованные данные или ключи)",
    ),
    (
        "STORAGE_SENSITIVE",
        r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["\'](?:token|auth|password|session|secret|key|user|uid|jwt)["\']',
        "Чувствительные ключи в localStorage/sessionStorage",
    ),
    (
        "POSTMESSAGE_HANDLER",
        r'addEventListener\s*\(\s*["\']message["\']',
        "Обработчики postMessage (проверить валидацию event.origin)",
    ),
    (
        "GRAPHQL",
        r'(?:query|mutation)\s+\w+\s*(?:\([^)]{0,100}\))?\s*\{',
        "GraphQL запросы/мутации",
    ),
    (
        "EVAL_USAGE",
        r'\beval\s*\(',
        "Использование eval() — потенциальный XSS sink",
    ),
    (
        "INNER_HTML",
        r'\.innerHTML\s*[+]?=\s*(?!["\']<[a-z])',
        "Присвоение innerHTML переменной — потенциальный XSS sink",
    ),
    (
        "DOCUMENT_WRITE",
        r'\bdocument\.write(?:ln)?\s*\(',
        "Использование document.write — потенциальный XSS sink",
    ),
    (
        "OPEN_REDIRECT_SINK",
        r'(?:window\.location|location\.href|location\.replace|location\.assign)\s*=\s*(?:[a-zA-Z_$][a-zA-Z0-9_$]*|`[^`]*\$\{)',
        "Потенциальная точка Open Redirect (location присваивается переменная)",
    ),
    (
        "CORS_WILDCARD",
        r'["\']Access-Control-Allow-Origin["\'][^"\']*["\']\*["\']',
        "CORS wildcard в коде",
    ),
    (
        "SOURCE_MAP",
        r'//[#@]\s*sourceMappingURL=\S+\.map',
        "Ссылка на source map (может раскрыть исходный код)",
    ),
    (
        "FETCH_WITH_CREDS",
        r'credentials\s*:\s*["\']include["\']',
        "fetch() с credentials:include — проверить CSRF-защиту",
    ),
    (
        "PROTOTYPE_POLLUTION",
        r'(?:__proto__|constructor\[[\'""]prototype[\'""]|Object\.assign\([^,]+,\s*(?:req|request|params|query|body))',
        "Потенциальная prototype pollution",
    ),
    (
        "POSTMESSAGE_OPEN_REDIRECT",
        r'(?:window\.location|location\.href|location\.replace|location\.assign)\s*=\s*(?:e|event|msg|message)\.data\.\w+',
        "postMessage open redirect — location присваивается e.data.* (проверить наличие e.origin валидации)",
    ),
    (
        "POSTMESSAGE_WILDCARD",
        r'\.postMessage\s*\([^,]+,\s*["\'][\*]["\']',
        "postMessage с targetOrigin='*' — данные видны любому фрейму",
    ),
    (
        "ADMIN_ROLE_CHECK",
        r'(?:\.role|roles|userRole)\.includes\s*\(\s*["\'][^"\']*admin|isAdmin\s*[=!]==?\s*true|["\']admin["\']\s*===?\s*role',
        "Клиентская проверка admin-роли — роль и её формат видны в JS",
    ),
    (
        "SENTRY_DSN",
        r'https://[a-f0-9]{32}@[a-zA-Z0-9][a-zA-Z0-9._-]*/\d+',
        "Sentry DSN — раскрывает инфраструктуру мониторинга (версия, окружение, self-hosted хост)",
    ),
    (
        "STRIPE_PUBKEY",
        r'\bpk_(?:live|test)_[A-Za-z0-9]{50,}\b',
        "Stripe publishable key (pk_live/pk_test) — публичный, но подтверждает платёжный стек",
    ),
    (
        "RECAPTCHA_SITEKEY",
        r'\b6L[a-zA-Z0-9_-]{38}\b',
        "Google reCAPTCHA v2/v3 site key — полезно при анализе обходов captcha",
    ),
]


def scan_file(filepath, patterns):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                for name, pattern, desc in patterns:
                    for match in pattern.finditer(line):
                        findings.append((name, desc, filepath, lineno, match.group(0)[:300]))
    except Exception:
        pass
    return findings


def main():
    parser = argparse.ArgumentParser(description="Custom JS regex scanner for pentest")
    parser.add_argument("directory", help="Directory with .js files")
    parser.add_argument("-o", "--output", help="Write results to file")
    args = parser.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: not a directory: {args.directory}", file=sys.stderr)
        sys.exit(1)

    compiled = [
        (name, re.compile(pattern, re.IGNORECASE), desc)
        for name, pattern, desc in PATTERNS
    ]

    js_files = []
    for root, _, files in os.walk(args.directory):
        for fname in sorted(files):
            if fname.endswith(".js"):
                js_files.append(os.path.join(root, fname))

    all_findings = []
    for filepath in js_files:
        all_findings.extend(scan_file(filepath, compiled))

    lines = []
    if not all_findings:
        lines.append("No findings.")
    else:
        by_type = {}
        for name, desc, filepath, lineno, match in all_findings:
            by_type.setdefault((name, desc), []).append((filepath, lineno, match))

        total = sum(len(v) for v in by_type.values())
        lines.append(f"Total findings: {total} across {len(by_type)} categories\n")

        for (type_name, desc), items in sorted(by_type.items()):
            lines.append(f"{'='*60}")
            lines.append(f"[{type_name}] {desc}  ({len(items)} hits)")
            lines.append(f"{'='*60}")
            shown = items[:30]
            for filepath, lineno, match in shown:
                fname = os.path.relpath(filepath, args.directory)
                lines.append(f"  {fname}:{lineno}")
                lines.append(f"    → {match.strip()}")
            if len(items) > 30:
                lines.append(f"  ... and {len(items) - 30} more (see output file)")
            lines.append("")

    result = "\n".join(lines) + "\n"
    print(result, end="")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(result)


if __name__ == "__main__":
    main()
