---
name: security-check
description: HTML/JS 파일을 4가지 보안 관점(하드코딩된 비밀번호·API 키, escape 없이 innerHTML에 넣는 사용자 입력(XSS), console.log의 민감 정보 노출, http://로 시작하는 외부 요청)으로 점검하고 결과를 🔴 심각 / 🟡 주의 / 🟢 제안 + 파일:라인 근거로 보고한다. 사용자가 "보안 점검", "security check"라고 말하거나, 코드를 배포 전에 보안 관점에서 검수하고 싶어하거나, 비밀번호/API 키 노출·XSS·민감정보 로깅·평문 HTTP 통신 여부를 확인하고 싶어할 때 이 스킬을 사용할 것.
---

# Security Check

정적 HTML/JS 파일을 4가지 관점에서 점검하고, 문제를 심각도별로 분류해서 한국어로 보고하는 스킬입니다. 초보자용 프로젝트에서 가장 흔히 발생하면서 동시에 정규식으로 객관적으로 검증 가능한 항목만 골랐습니다: 하드코딩된 비밀번호/API 키, innerHTML을 통한 XSS, console.log의 민감 정보 노출, http://(비TLS) 외부 요청.

## 사용 순서

1. **대상 파일 찾기**: 사용자가 파일을 지정했으면 그 파일을, 지정하지 않았으면 현재 디렉터리(또는 프로젝트 루트)의 `*.html`, `*.js` 파일을 찾아 전부 점검 대상에 포함합니다.

2. **점검 스크립트 실행**: 판단을 스크립트에 맡기세요 — 눈대중으로 훑지 말고 아래 스크립트를 실행해서 나온 JSON을 그대로 근거로 씁니다.

   ```
   python <skill_dir>/scripts/check_security.py <file1> [file2 ...]
   ```

   출력은 파일별 JSON 객체 배열이며, 각 파일마다 `checks.hardcoded_secrets`, `checks.xss_innerhtml`, `checks.console_log_sensitive`, `checks.http_external` 네 개의 결과를 담고 있습니다. 각 결과는 `status`(`pass`/`fail`)와 `items` 배열(문제가 있으면 `line`, `snippet` 등 근거 포함)을 가집니다.

3. **JSON을 사람이 읽을 보고서로 변환**: 아래 "메시지 템플릿"을 참고해서 각 항목을 심각도별로 묶어 정리하세요.

## 메시지 템플릿

`{}`는 JSON 값으로 채우는 자리입니다. 파일:라인 형태로 근거를 반드시 남기세요 (예: `expense.html:42`).

**hardcoded_secrets** (`items` 배열의 각 원소마다 한 줄씩, 항상 🔴 심각)
- 🔴 [하드코딩된 비밀 정보] `{file}:{line}` — `{kind}`로 보이는 값이 코드에 직접 노출되어 있습니다: `{snippet}` → 환경 변수나 서버 사이드 설정으로 옮기고, 이미 커밋되었다면 즉시 키를 폐기(rotate)하세요.
- `items`가 비어 있으면 통과.

**xss_innerhtml** (`items` 배열의 각 원소마다 한 줄씩, 항상 🔴 심각)
- 🔴 [XSS 위험] `{file}:{line}` — escape 없이 동적 값을 `innerHTML`에 대입하고 있습니다: `{snippet}` → 사용자 입력이 섞여 있다면 `textContent`로 바꾸거나, HTML이 꼭 필요하면 DOMPurify 등으로 sanitize한 뒤 대입하세요.
- `items`가 비어 있으면 통과.

**console_log_sensitive** (`items` 배열의 각 원소마다 한 줄씩, 항상 🟡 주의)
- 🟡 [민감 정보 로깅] `{file}:{line}` — `{kind}`로 보이는 값을 `console.log`로 출력하고 있습니다: `{snippet}` → 브라우저 개발자 도구나 로그 수집기에 그대로 남을 수 있으니 제거하거나 마스킹하세요.
- `items`가 비어 있으면 통과.

**http_external** (`items` 배열의 각 원소마다 한 줄씩, 원소별 `severity`로 분기)
- `severity: "warning"` → 🟡 [평문 HTTP 요청] `{file}:{line}` — `fetch`/`XMLHttpRequest`/`axios` 등으로 `{url}`에 암호화되지 않은 요청을 보냅니다: `{snippet}` → 가능하면 https://로 변경하세요. 도청·변조(MITM) 위험이 있습니다.
- `severity: "suggestion"` → 🟢 [http:// 링크 확인] `{file}:{line}` — `{url}`이 http://로 시작합니다: `{snippet}` → 리소스가 정말 TLS를 지원하지 않는지 확인 후, 가능하면 https://로 바꾸는 것을 권장합니다.
- `items`가 비어 있으면 통과.

## 보고서 형식

파일마다 아래 형식을 사용하세요. 항목이 없는 심각도는 통째로 생략해도 됩니다.

```
## 🔒 보안 점검 결과 — {파일명}

🔴 심각 ({개수})
- ...

🟡 주의 ({개수})
- ...

🟢 제안 ({개수})
- ...

✅ 통과: {통과한 항목 이름들을 쉼표로}
```

여러 파일을 점검했다면 파일별 보고서 뒤에 "총 N개 파일, 🔴 A개 / 🟡 B개 / 🟢 C개" 형태의 전체 요약을 한 줄 덧붙이세요.

## 주의할 점

- 이 스킬은 **점검(읽기 전용)** 이 기본 동작입니다. 파일을 자동으로 고치지 마세요. 보고서 마지막에 "원하시면 바로 수정해드릴까요?"처럼 한 번 물어보고, 사용자가 동의하면 그때 직접 수정하세요.
- 정규식 기반 점검이라 완벽한 JS 파서가 아닙니다. 여러 줄에 걸친 `console.log(...)`나 `innerHTML` 대입, 복잡한 표현식은 놓칠 수 있습니다. JSON 결과가 이상하게 느껴지면(과탐/누락) 스크립트를 맹신하지 말고 직접 파일을 열어 확인하세요.
- 값이 `YOUR_API_KEY`, `changeme`, `example` 같은 플레이스홀더면 하드코딩 항목에서 자동으로 제외됩니다 — 진짜 값처럼 보이는데도 제외됐다면 직접 확인하세요.
- `http://localhost`, `http://127.0.0.1`은 로컬 개발 환경으로 간주해 제외합니다.
- `python`이 없는 환경이면 스크립트 대신 파일을 직접 읽고 같은 4가지 기준(비밀번호/API 키 리터럴, innerHTML 동적 대입, console.log의 민감 변수, http:// 리터럴)으로 수동 점검하세요.
