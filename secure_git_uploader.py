import os
import re
import stat
import shutil
import tempfile
import subprocess
import tkinter as tk
from tkinter import filedialog

# 검사할 파일 확장자
SCAN_EXTENSIONS = (
    ".py", ".txt", ".bat", ".json", ".env", ".ini", ".cfg",
    ".yaml", ".yml", ".ps1", ".js", ".ts", ".md"
)

# 제외할 폴더
EXCLUDE_DIRS = {
    ".git", "__pycache__", "node_modules", "dist", "build", ".venv", "venv"
}

# 이메일
EMAIL_PATTERN = re.compile(
    r'(?i)\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
)

# Bearer [REDACTED]
BEARER_PATTERN = re.compile(
    r'(?i)(Bearer\s+)([A-Za-z0-9._\-]+)'
)

# Google API key
GOOGLE_API_PATTERN = re.compile(
    r'\bAIza[0-9A-Za-z\-_]{20,}\b'
)

# 일반 key=value / key: value 형태
GENERIC_SECRET_PATTERN = re.compile(
    r'''(?ix)
    \b(
        password|passwd|pwd|pw|
        secret|client_secret|clientsecret|
        api_key|apikey|access_token|token|
        private_key|privatekey|
        auth_token|auth|bearer|
        username|user|userid|user_id|
        login|login_id|id|email
    )\b
    (\s*[:=]\s*)
    (
        "(?:[^"\\]|\\.)*" |
        '(?:[^'\\]|\\.)*' |
        [^\s,\}\]\)\r\n]+
    )
    '''
)

# JSON 스타일 "key": "value"
JSON_SECRET_PATTERN = re.compile(
    r'''(?ix)
    ("
        (?:password|passwd|pwd|pw|secret|client_secret|clientsecret|
        api_key|apikey|access_token|token|private_key|privatekey|
        auth_token|auth|bearer|username|user|userid|user_id|
        login|login_id|id|email)
    "\s*:\s*)
    (
        "(?:[^"\\]|\\.)*" |
        '(?:[^'\\]|\\.)*' |
        [^\s,\}\]\)\r\n]+
    )
    '''
)

def should_scan(file_name: str) -> bool:
    lower = file_name.lower()
    if lower.startswith(".env"):
        return True
    return lower.endswith(SCAN_EXTENSIONS)

def redact_match(m):
    return f'{m.group(1)}{m.group(2)}"[REDACTED]"'

def redact_json_match(m):
    return f'{m.group(1)}"[REDACTED]"'

def clean_content(content: str):
    total_hits = 0
    cleaned = content

    cleaned, count = EMAIL_PATTERN.subn("[REDACTED_EMAIL]", cleaned)
    total_hits += count

    cleaned, count = BEARER_PATTERN.subn(r"\1[REDACTED]", cleaned)
    total_hits += count

    cleaned, count = GOOGLE_API_PATTERN.subn("[REDACTED_API_KEY]", cleaned)
    total_hits += count

    cleaned, count = JSON_SECRET_PATTERN.subn(redact_json_match, cleaned)
    total_hits += count

    cleaned, count = GENERIC_SECRET_PATTERN.subn(redact_match, cleaned)
    total_hits += count

    return cleaned, total_hits

def remove_readonly(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

def run_upload():
    source_path = None
    temp_path = None
    original_cwd = os.getcwd()

    root = tk.Tk()
    root.withdraw()
    source_path = filedialog.askdirectory(title="업로드할 폴더 선택")
    root.destroy()

    if not source_path:
        print("취소됨")
        return

    repo_name = os.path.basename(source_path).replace(" ", "-")

    # 매번 새 임시폴더 생성
    temp_path = tempfile.mkdtemp(prefix="github_upload_")

    try:
        # 원본 복사
        shutil.copytree(
            source_path,
            temp_path,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                ".git", "__pycache__", "node_modules", "dist", "build", ".venv", "venv"
            )
        )

        print(f"\n🧹 보안 세탁 시작: {source_path}")
        print(f"📂 임시 작업 경로: {temp_path}")

        file_changed_count = 0
        total_redactions = 0

        # 파일 검사
        for root_dir, dirs, files in os.walk(temp_path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

            for file in files:
                if not should_scan(file):
                    continue

                file_path = os.path.join(root_dir, file)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    cleaned, hits = clean_content(content)

                    if hits > 0:
                        with open(file_path, "w", encoding="utf-8") as f:
                            f.write(cleaned)

                        file_changed_count += 1
                        total_redactions += hits
                        print(f"  ✅ 가림 처리: {file_path}  ({hits}개)")
                except Exception as e:
                    print(f"  ⚠️ 파일 검사 실패: {file_path} / {e}")

        print(f"\n총 수정 파일 수: {file_changed_count}")
        print(f"총 가림 처리 수: {total_redactions}")

        os.chdir(temp_path)

        is_private = input("\n❓ 비공개(Private)로 설정할까요? (Y/N): ").strip().lower() == "y"
        visibility = "--private" if is_private else "--public"

        # gitignore 생성
        with open(".gitignore", "w", encoding="utf-8") as f:
            f.write(
                ".env\n"
                ".env.*\n"
                "__pycache__/\n"
                "node_modules/\n"
                "dist/\n"
                "build/\n"
                ".venv/\n"
                "venv/\n"
                "*.log\n"
                "*.sqlite3\n"
                "*.db\n"
            )

        subprocess.run(["git", "init"], check=True)
        subprocess.run(["git", "add", "."], check=True)
        subprocess.run(["git", "commit", "-m", "Secure upload with redacted secrets"], check=True)
        subprocess.run(["git", "branch", "-M", "main"], check=True)

        print(f"\n🚀 GitHub에 '{repo_name}' 생성 및 업로드 중...")
        subprocess.run(
            ["gh", "repo", "create", repo_name, visibility, "--source=.", "--remote=origin", "--push"],
            check=True
        )

        repo_url = subprocess.run(
            ["gh", "repo", "view", "--json", "url", "-q", ".url"],
            capture_output=True,
            text=True,
            check=True
        ).stdout.strip()

        print("\n✨ 완료")
        print(f"🔗 {repo_url}")
        print("※ GitHub에서 민감정보가 실제로 가려졌는지 꼭 한 번 확인해.")

    except subprocess.CalledProcessError as e:
        print(f"\n❌ 명령 실행 오류: {e}")
    except Exception as e:
        print(f"\n❌ 오류: {e}")
    finally:
        try:
            os.chdir(original_cwd)
        except Exception:
            pass

        if temp_path and os.path.exists(temp_path):
            try:
                shutil.rmtree(temp_path, onerror=remove_readonly)
            except Exception as cleanup_error:
                print(f"⚠️ 임시 폴더 삭제 실패: {cleanup_error}")

if __name__ == "__main__":
    run_upload()