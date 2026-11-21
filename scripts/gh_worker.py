import os
import sys
import json
import time
import re
import socket
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
import subprocess
import shutil
import pathlib
import mimetypes
import random
from typing import Optional, List, Dict, Any, Tuple

# Configuration
JOB_ID = os.environ.get("JOB_ID", "").strip()
WORKER_URL = os.environ.get("WORKER_URL", "").strip().rstrip("/")
API_SECRET = os.environ.get("API_SECRET", "").strip()

GDRIVE_CLIENT_ID = os.environ.get("GDRIVE_CLIENT_ID", "").strip()
GDRIVE_CLIENT_SECRET = os.environ.get("GDRIVE_CLIENT_SECRET", "").strip()
GDRIVE_REFRESH_TOKEN = os.environ.get("GDRIVE_REFRESH_TOKEN", "").strip()

CHUNK_SIZE = 128 * 1024 * 1024  # 128 MiB (134,217,728 bytes, exact multiple of 256 KiB)
RUNNER_START_TIME = time.monotonic()

_CURRENT_SUBPROC: Optional[subprocess.Popen] = None
_CURRENT_SESSION_URL: Optional[str] = None


class ControlAbort(Exception):
    """Raised when Cloudflare Edge returns a control signal to abort execution cooperatively."""
    def __init__(self, signal: str):
        self.signal = signal
        super().__init__(f"Aborted by control signal: {signal}")


def abort_active_resources(session_url: Optional[str] = None) -> None:
    global _CURRENT_SUBPROC, _CURRENT_SESSION_URL
    if _CURRENT_SUBPROC and _CURRENT_SUBPROC.poll() is None:
        try:
            _CURRENT_SUBPROC.terminate()
            _CURRENT_SUBPROC.wait(timeout=2.0)
        except Exception:
            try:
                _CURRENT_SUBPROC.kill()
            except Exception:
                pass
        _CURRENT_SUBPROC = None

    target_session = session_url or _CURRENT_SESSION_URL
    if target_session:
        try:
            req = urllib.request.Request(target_session, headers={"Content-Length": "0"}, method="DELETE")
            with urllib.request.urlopen(req, timeout=10) as _:
                pass
        except Exception:
            pass
        _CURRENT_SESSION_URL = None


def log_state(job_id: str, state: str, code: Optional[str] = None) -> None:
    """Strictly silent public log: prints ONLY opaque job_id prefix and state name (and optional code)."""
    jid = job_id[:8] if job_id else "unknown"
    if code:
        sys.stdout.write(f"[dg] job={jid} state={state} code={code}\n")
    else:
        sys.stdout.write(f"[dg] job={jid} state={state}\n")
    sys.stdout.flush()


def sanitize_text(text: str) -> str:
    if not text:
        return ""
    cleaned = str(text)
    for secret in [API_SECRET, GDRIVE_CLIENT_SECRET, GDRIVE_REFRESH_TOKEN, GDRIVE_CLIENT_ID]:
        if secret and len(secret) > 4:
            cleaned = cleaned.replace(secret, "[REDACTED]")
    cleaned = re.sub(r'(\?|&)(token|key|sig|secret|auth|signature)=[^&\s]+', r'\1\2=[REDACTED]', cleaned, flags=re.IGNORECASE)
    return cleaned[:1000]


def is_drive_retryable_error(status: int, body: str) -> bool:
    """Checks whether a Google Drive error should trigger exponential backoff retry."""
    if "storageQuotaExceeded" in body:
        return False
    if status in (429, 500, 502, 503, 504):
        return True
    if status == 403:
        b_low = body.lower()
        b_no_space = b_low.replace(" ", "")
        retryable_tokens = (
            "ratelimitexceeded",
            "userratelimitexceeded",
            "quota exceeded",
            "quotaexceeded",
            "queries",
            "backenderror",
            "sharingratelimitexceeded"
        )
        return any(t in b_low or t in b_no_space for t in retryable_tokens)
    return False


def is_ssrf_safe_url(url_str: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url_str)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            ip_str = entry[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if not ip_obj.is_global or ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                return False
        return True
    except Exception:
        return False


def sanitize_filename(name: str, max_len: int = 120) -> str:
    if not name:
        return ""
    clean = re.sub(r'[\x00-\x1f\x7f]', '', name)
    clean = re.sub(r'[\\/*?:"<>|]', '', clean)
    clean = re.sub(r'\s+', ' ', clean)
    clean = clean.strip(" .-")
    if len(clean) > max_len:
        clean = clean[:max_len].strip(" .-")
    return clean


def is_generic_title(name: str) -> bool:
    if not name:
        return True
    s = name.strip().lower()
    if not s:
        return True
    generic_words = {
        "master", "index", "playlist", "hls", "video", "stream",
        "media", "chunklist", "manifest", "audio", "output"
    }
    base = s.rsplit(".", 1)[0]
    if base in generic_words:
        return True
    if re.match(r'^(index|hls|master|video|stream)[-_].*', base):
        return True
    return False


def call_api(endpoint: str, data: Optional[dict] = None) -> dict:
    url = f"{WORKER_URL}{endpoint}"
    req_body = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {
        "X-API-Key": API_SECRET,
        "Accept": "application/json",
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    }
    if req_body:
        headers["Content-Type"] = "application/json"

    res_data: dict = {}
    for attempt in range(1, 4):
        try:
            req = urllib.request.Request(url, data=req_body, headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 204:
                    res_data = {}
                    break
                resp_bytes = resp.read()
                res_data = json.loads(resp_bytes.decode("utf-8")) if resp_bytes else {}
                break
        except urllib.error.HTTPError as he:
            if he.code == 204:
                res_data = {}
                break
            if attempt == 3:
                raise
        except Exception:
            if attempt == 3:
                raise
        time.sleep(1.5 * attempt)

    # Check for cooperative control signal
    control = res_data.get("control", "")
    if control in ("pause", "stop", "deleted"):
        raise ControlAbort(control)

    return res_data


class GoogleDriveUploader:
    def __init__(self, client_id: str, client_secret: str, refresh_token: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.refresh_token = refresh_token
        self.access_token: Optional[str] = None
        self.token_expiry: float = 0.0

    def get_access_token(self, force_refresh: bool = False) -> str:
        now = time.monotonic()
        if not force_refresh and self.access_token and now < self.token_expiry - 60:
            return self.access_token

        token_url = "https://oauth2.googleapis.com/token"
        params = urllib.parse.urlencode({
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
            "grant_type": "refresh_token"
        }).encode("utf-8")

        req = urllib.request.Request(token_url, data=params, headers={"Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            self.access_token = data["access_token"]
            expires_in = int(data.get("expires_in", 3600))
            self.token_expiry = now + expires_in
            return self.access_token

    def initiate_resumable_session(self, filename: str, folder_id: str, content_type: str, file_size: int, job_id: str) -> str:
        url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable"
        metadata: Dict[str, Any] = {"name": filename}
        if folder_id and folder_id != "root":
            metadata["parents"] = [folder_id]

        body = json.dumps(metadata).encode("utf-8")

        for attempt in range(1, 9):
            token = self.get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=UTF-8",
                "X-Upload-Content-Type": content_type or "application/octet-stream",
                "X-Upload-Content-Length": str(file_size)
            }
            req = urllib.request.Request(url, data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    loc = resp.headers.get("Location")
                    if not loc:
                        raise RuntimeError("No Location header returned in Google Drive resumable session")
                    return loc
            except urllib.error.HTTPError as he:
                err_body = he.read().decode("utf-8", errors="replace")
                if he.code == 401 and attempt == 1:
                    self.get_access_token(force_refresh=True)
                    continue
                if is_drive_retryable_error(he.code, err_body) and attempt < 8:
                    retry_after = he.headers.get("Retry-After")
                    if retry_after and retry_after.isdigit():
                        delay = min(90.0, float(retry_after))
                    else:
                        delay = min(90.0, (2 ** attempt) * 2.5) + random.uniform(0.5, 2.5)
                    call_api(f"/internal/update/{job_id}", {
                        "phase_detail": f"Drive quota backoff ({int(delay)}s)..."
                    })
                    log_state(job_id, "retry_backoff", f"DRIVE_{he.code}")
                    time.sleep(delay)
                    continue
                raise RuntimeError(f"Google Drive initiate session error {he.code}: {err_body[:200]}")
            except Exception as e:
                if attempt < 8:
                    delay = min(90.0, (2 ** attempt) * 2.5) + random.uniform(0.5, 2.5)
                    time.sleep(delay)
                    continue
                raise
        raise RuntimeError("Google Drive initiate session failed after retries")

    def upload_file(self, file_path: str, filename: str, folder_id: str, job_id: str, on_progress=None) -> Dict[str, Any]:
        global _CURRENT_SESSION_URL
        file_size = os.path.getsize(file_path)
        content_type, _ = mimetypes.guess_type(file_path)
        if not content_type:
            content_type = "video/mp4" if file_path.lower().endswith((".mp4", ".mkv", ".webm")) else "application/octet-stream"

        session_url = self.initiate_resumable_session(filename, folder_id, content_type, file_size, job_id)
        _CURRENT_SESSION_URL = session_url

        offset = 0
        last_report = time.monotonic()

        with open(file_path, "rb") as f:
            while offset < file_size:
                f.seek(offset)
                chunk_data = f.read(CHUNK_SIZE)
                chunk_len = len(chunk_data)
                end = offset + chunk_len - 1

                headers = {
                    "Content-Length": str(chunk_len),
                    "Content-Range": f"bytes {offset}-{end}/{file_size}"
                }

                chunk_uploaded = False
                for attempt in range(1, 9):
                    req = urllib.request.Request(session_url, data=chunk_data, headers=headers, method="PUT")
                    try:
                        with urllib.request.urlopen(req, timeout=120) as resp:
                            if resp.status in (200, 201):
                                data = json.loads(resp.read().decode("utf-8"))
                                _CURRENT_SESSION_URL = None
                                return data
                    except urllib.error.HTTPError as he:
                        if he.code == 308:
                            range_hdr = he.headers.get("Range")
                            if range_hdr:
                                m = re.search(r'bytes=0-(\d+)', range_hdr)
                                if m:
                                    offset = int(m.group(1)) + 1
                                else:
                                    offset += chunk_len
                            else:
                                offset += chunk_len
                            chunk_uploaded = True
                            break
                        
                        err_body = he.read().decode("utf-8", errors="replace")
                        if is_drive_retryable_error(he.code, err_body) and attempt < 8:
                            retry_after = he.headers.get("Retry-After")
                            if retry_after and retry_after.isdigit():
                                delay = min(90.0, float(retry_after))
                            else:
                                delay = min(90.0, (2 ** attempt) * 2.5) + random.uniform(0.5, 2.5)
                            
                            call_api(f"/internal/update/{job_id}", {
                                "phase_detail": f"Drive quota backoff ({int(delay)}s)..."
                            })
                            log_state(job_id, "retry_backoff", f"DRIVE_{he.code}")
                            time.sleep(delay)

                            # Probe session offset with empty Content-Range
                            probe_req = urllib.request.Request(
                                session_url,
                                data=b"",
                                headers={"Content-Range": f"bytes */{file_size}"},
                                method="PUT"
                            )
                            try:
                                with urllib.request.urlopen(probe_req, timeout=30) as p_resp:
                                    if p_resp.status in (200, 201):
                                        data = json.loads(p_resp.read().decode("utf-8"))
                                        _CURRENT_SESSION_URL = None
                                        return data
                            except urllib.error.HTTPError as p_he:
                                if p_he.code == 308:
                                    p_range = p_he.headers.get("Range")
                                    if p_range:
                                        pm = re.search(r'bytes=0-(\d+)', p_range)
                                        if pm:
                                            offset = int(pm.group(1)) + 1
                                            f.seek(offset)
                                            chunk_data = f.read(CHUNK_SIZE)
                                            chunk_len = len(chunk_data)
                                            end = offset + chunk_len - 1
                                            headers = {
                                                "Content-Length": str(chunk_len),
                                                "Content-Range": f"bytes {offset}-{end}/{file_size}"
                                            }
                            continue
                        raise RuntimeError(f"Google Drive chunk upload error {he.code}: {err_body[:200]}")
                    except Exception as e:
                        if isinstance(e, ControlAbort):
                            raise
                        if attempt < 8:
                            delay = min(90.0, (2 ** attempt) * 2.5) + random.uniform(0.5, 2.5)
                            time.sleep(delay)
                            continue
                        raise

                now = time.monotonic()
                if now - last_report >= 2.0:
                    last_report = now
                    pct = min(99.0, 50.0 + (offset / file_size * 50.0))
                    if on_progress:
                        on_progress(pct, offset, file_size)

        _CURRENT_SESSION_URL = None
        return {}


def rebuild_video(input_path: str) -> str:
    """Lossless rebuild via ffmpeg to sanitize PTS timestamps and faststart moov atom."""
    if not os.path.exists(input_path) or os.path.getsize(input_path) < 10240:
        return input_path

    if shutil.which("ffmpeg") is None:
        return input_path

    rebuilt_path = f"{input_path}.rebuilt.mp4"
    cmd = [
        "ffmpeg", "-y", "-err_detect", "ignore_err",
        "-i", input_path,
        "-c", "copy",
        "-avoid_negative_ts", "make_zero",
        "-movflags", "+faststart",
        rebuilt_path
    ]
    global _CURRENT_SUBPROC
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        _CURRENT_SUBPROC = proc
        proc.wait(timeout=600)
        _CURRENT_SUBPROC = None
        if proc.returncode == 0 and os.path.exists(rebuilt_path) and os.path.getsize(rebuilt_path) > 10240:
            shutil.move(rebuilt_path, input_path)
            return input_path
    except Exception:
        pass
    finally:
        _CURRENT_SUBPROC = None
        if os.path.exists(rebuilt_path):
            try:
                os.remove(rebuilt_path)
            except Exception:
                pass
    return input_path


def verify_video_integrity(file_path: str) -> bool:
    """3-point real-frame seek decoding verification (1s, 50%, end-5s)."""
    if not os.path.exists(file_path) or os.path.getsize(file_path) < 10240:
        return False

    if shutil.which("ffprobe") is None or shutil.which("ffmpeg") is None:
        return os.path.getsize(file_path) > 10240

    cmd_probe = [
        "ffprobe", "-v", "error",
        "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1",
        file_path
    ]
    try:
        res = subprocess.run(cmd_probe, capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return False
        dur_str = res.stdout.strip()
        duration = float(dur_str) if dur_str else 0.0
        if duration <= 1.0:
            return False

        points = [1.0, round(duration / 2.0, 2), max(1.0, round(duration - 5.0, 2))]
        for pt in points:
            check_cmd = [
                "ffmpeg", "-v", "error",
                "-ss", str(pt),
                "-i", file_path,
                "-vframes", "1",
                "-f", "null", "-"
            ]
            c_res = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            if c_res.returncode != 0:
                return False
        return True
    except Exception:
        return False


def resolve_with_playwright(candidate_urls: List[str], page_url: Optional[str], cookies: Optional[str], user_agent: Optional[str]) -> Optional[Dict[str, Any]]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    valid = [u for u in candidate_urls if u and is_ssrf_safe_url(u)]
    if not valid:
        return None

    to_visit = valid[:2]
    captured_streams: List[Dict[str, Any]] = []

    try:
        with sync_playwright() as p:
            custom_exec = os.getenv("PLAYWRIGHT_CHROME_PATH")
            launch_kwargs: Dict[str, Any] = {
                "headless": True,
                "args": ["--no-sandbox", "--disable-dev-shm-usage", "--autoplay-policy=no-user-gesture-required"]
            }
            if custom_exec and os.path.exists(custom_exec):
                launch_kwargs["executable_path"] = custom_exec

            browser = p.chromium.launch(**launch_kwargs)
            try:
                desktop_ua = user_agent or "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                context = browser.new_context(user_agent=desktop_ua, viewport={"width": 1280, "height": 720})

                if cookies and page_url and page_url.startswith(("http://", "https://")):
                    try:
                        cookie_list = []
                        for pair in cookies.split(";"):
                            if "=" in pair:
                                k, v = pair.split("=", 1)
                                k_s, v_s = k.strip(), v.strip()
                                if k_s:
                                    cookie_list.append({"name": k_s, "value": v_s, "url": page_url})
                        if cookie_list:
                            context.add_cookies(cookie_list)
                    except Exception:
                        pass

                def on_response(response):
                    try:
                        u = response.url
                        u_low = u.lower()
                        if response.status in (200, 206) and any(ext in u_low for ext in (".m3u8", ".mpd", ".mp4")):
                            if is_ssrf_safe_url(u):
                                captured_streams.append({
                                    "url": u,
                                    "status": response.status,
                                    "referer": response.request.headers.get("referer"),
                                    "user_agent": response.request.headers.get("user-agent")
                                })
                    except Exception:
                        pass

                context.on("response", on_response)
                page = context.new_page()

                start = time.monotonic()
                for target in to_visit:
                    if time.monotonic() - start > 20.0 or captured_streams:
                        break
                    try:
                        page.goto(target, wait_until="domcontentloaded", timeout=15000)
                    except Exception:
                        continue

                    for selector in ("video", '[class*="play"]', 'button[aria-label*="Play"]'):
                        try:
                            el = page.query_selector(selector)
                            if el and el.is_visible():
                                el.click(timeout=1500)
                                break
                        except Exception:
                            pass

                    for _ in range(8):
                        if captured_streams:
                            break
                        time.sleep(0.5)

            finally:
                browser.close()
    except Exception:
        pass

    if captured_streams:
        return captured_streams[0]
    return None


def execute_single_download(job: Dict[str, Any], uploader: GoogleDriveUploader) -> None:
    global _CURRENT_SUBPROC
    job_id = job["job_id"]
    raw_url = job.get("url", "")
    folder_id = job.get("folder_id", "root")
    title = job.get("title", "")
    filename = job.get("filename", "")
    user_agent = job.get("user_agent")
    referer = job.get("referer")
    cookies = job.get("cookies")
    page_url = job.get("page_url")

    job_dir = f"/tmp/drivegrab/{job_id}"
    os.makedirs(job_dir, exist_ok=True)

    try:
        log_state(job_id, "downloading")
        call_api(f"/internal/update/{job_id}", {
            "status": "downloading",
            "phase_detail": "Downloading via runner"
        })

        safe_name = sanitize_filename(filename or title)
        out_tmpl = f"{safe_name}.%(ext)s" if safe_name else "%(title)s.%(ext)s"

        cmd = [
            sys.executable, "-m", "yt_dlp",
            "-f", "bv*[ext=mp4]+ba[ext=m4a]/b[ext=mp4]/bv*+ba/b",
            "--no-playlist",
            "--concurrent-fragments", "8",
            "--merge-output-format", "mp4",
            "-P", job_dir,
            "-o", out_tmpl,
        ]
        if user_agent:
            cmd.extend(["--user-agent", user_agent])
        if referer:
            cmd.extend(["--add-header", f"Referer:{referer}"])
        if cookies:
            cmd.extend(["--add-header", f"Cookie:{cookies}"])
        cmd.extend(["--", raw_url])

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        _CURRENT_SUBPROC = proc
        last_hb = time.monotonic()
        while proc.poll() is None:
            time.sleep(0.5)
            now = time.monotonic()
            if now - last_hb >= 2.0:
                last_hb = now
                call_api(f"/internal/update/{job_id}", {
                    "status": "downloading",
                    "phase_detail": "Downloading via runner"
                })
        _CURRENT_SUBPROC = None
        stderr_text = proc.stderr.read() if proc.stderr else ""
        success = (proc.returncode == 0)

        # Fallback to Playwright if stream resolution failed
        if not success:
            log_state(job_id, "resolving_stream")
            pw_stream = resolve_with_playwright([referer, page_url, raw_url], page_url, cookies, user_agent)
            if pw_stream and pw_stream.get("url"):
                stream_url = pw_stream["url"]
                cmd_pw = [
                    sys.executable, "-m", "yt_dlp",
                    "-f", "bv*[ext=mp4]+ba[ext=m4a]/b[ext=mp4]/bv*+ba/b",
                    "--no-playlist",
                    "-P", job_dir,
                    "-o", out_tmpl,
                    "--", stream_url
                ]
                proc_pw = subprocess.Popen(cmd_pw, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                _CURRENT_SUBPROC = proc_pw
                last_hb = time.monotonic()
                while proc_pw.poll() is None:
                    time.sleep(0.5)
                    now = time.monotonic()
                    if now - last_hb >= 2.0:
                        last_hb = now
                        call_api(f"/internal/update/{job_id}", {
                            "status": "downloading",
                            "phase_detail": "Downloading via runner"
                        })
                _CURRENT_SUBPROC = None
                stderr_text = proc_pw.stderr.read() if proc_pw.stderr else ""
                success = (proc_pw.returncode == 0)

        if not success:
            err_msg = stderr_text[-400:] if stderr_text else "Download failed"
            raise RuntimeError(sanitize_text(err_msg))

        downloaded_files = [f for f in pathlib.Path(job_dir).rglob("*") if f.is_file()]
        if not downloaded_files:
            raise RuntimeError("No files downloaded by yt-dlp")

        target_file = max(downloaded_files, key=lambda f: f.stat().st_size)
        file_path = str(target_file)
        final_fn = target_file.name

        # Rebuild & Verify
        if target_file.suffix.lower() in (".mp4", ".mkv", ".webm", ".ts"):
            log_state(job_id, "rebuilding")
            file_path = rebuild_video(file_path)
            log_state(job_id, "verifying")
            if not verify_video_integrity(file_path):
                raise RuntimeError("Video failed 3-point seek integrity verification")

        # Upload
        log_state(job_id, "uploading")
        fsize = os.path.getsize(file_path)
        call_api(f"/internal/update/{job_id}", {
            "status": "uploading_to_gdrive",
            "filename": final_fn,
            "total_bytes": fsize,
            "phase_detail": "Uploading to Google Drive (128 MiB chunks)"
        })

        def on_upload_prog(pct, uploaded_b, tot_b):
            call_api(f"/internal/update/{job_id}", {
                "progress": pct,
                "downloaded_bytes": uploaded_b,
                "phase_detail": f"Uploading to Drive ({(uploaded_b / (1024*1024)):.1f} / {(tot_b / (1024*1024)):.1f} MB)"
            })

        res = uploader.upload_file(file_path, final_fn, folder_id, job_id, on_progress=on_upload_prog)
        if not res or not res.get("id"):
            raise RuntimeError("Google Drive upload failed to return file ID")

        log_state(job_id, "completed")
        call_api(f"/internal/update/{job_id}", {
            "status": "completed",
            "progress": 100.0,
            "downloaded_bytes": fsize,
            "total_bytes": fsize,
            "verified_size_bytes": fsize,
            "phase_detail": "Saved to Drive"
        })

    except ControlAbort:
        abort_active_resources()
        raise
    except Exception as e:
        log_state(job_id, "failed")
        clean_err = sanitize_text(str(e))
        call_api(f"/internal/update/{job_id}", {
            "status": "failed",
            "error": clean_err
        })
        raise
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)


def execute_batch_direct(job: Dict[str, Any], uploader: GoogleDriveUploader) -> None:
    global _CURRENT_SUBPROC
    job_id = job["job_id"]
    batch_id = job.get("batch_id", "")
    folder_id = job.get("folder_id", "root")
    items_json = job.get("batch_payload", "[]")
    items = json.loads(items_json) if items_json else []

    log_state(job_id, "batch_processing")
    completed = 0
    total = len(items)

    try:
        for idx, item in enumerate(items):
            # Check control signal before each item
            call_api(f"/internal/update/{job_id}", {
                "status": "downloading",
                "phase_detail": f"Processing item {idx+1}/{total}"
            })

            item_url = item.get("url", "")
            item_fn = item.get("filename") or item.get("title") or f"file_{idx+1}.mp4"
            safe_fn = sanitize_filename(item_fn)

            item_job_id = f"{job_id}_{idx}"
            job_dir = f"/tmp/drivegrab/{item_job_id}"
            os.makedirs(job_dir, exist_ok=True)
            try:
                log_state(job_id, f"item_{idx+1}_of_{total}")
                dest_path = os.path.join(job_dir, safe_fn)

                curl_cmd = ["curl", "-sSL", "-o", dest_path, item_url]
                if item.get("extra_cookie"):
                    curl_cmd.extend(["-H", f"Cookie: {item['extra_cookie']}"])

                proc = subprocess.Popen(curl_cmd)
                _CURRENT_SUBPROC = proc
                proc.wait(timeout=1200)
                _CURRENT_SUBPROC = None

                if os.path.exists(dest_path) and os.path.getsize(dest_path) > 1024:
                    if dest_path.lower().endswith((".mp4", ".mkv", ".webm")):
                        dest_path = rebuild_video(dest_path)
                    uploader.upload_file(dest_path, safe_fn, folder_id, job_id)
                    completed += 1

                prog = round((completed / total) * 100.0, 1)
                call_api(f"/internal/update/{job_id}", {
                    "progress": prog,
                    "phase_detail": f"Processed {completed}/{total} items"
                })
                if batch_id:
                    call_api(f"/internal/batch_update/{batch_id}", {
                        "completed_count": completed,
                        "active_detail": f"Completed {completed}/{total}"
                    })
            except ControlAbort:
                raise
            except Exception:
                pass
            finally:
                _CURRENT_SUBPROC = None
                shutil.rmtree(job_dir, ignore_errors=True)

        log_state(job_id, "completed")
        call_api(f"/internal/update/{job_id}", {
            "status": "completed",
            "progress": 100.0,
            "phase_detail": f"Batch completed ({completed}/{total} uploaded)"
        })
    except ControlAbort:
        abort_active_resources()
        raise


def main():
    if not JOB_ID or not WORKER_URL or not API_SECRET:
        sys.stderr.write("Missing mandatory environment variables\n")
        sys.exit(1)

    uploader = GoogleDriveUploader(GDRIVE_CLIENT_ID, GDRIVE_CLIENT_SECRET, GDRIVE_REFRESH_TOKEN)
    log_state(JOB_ID, "booting")

    try:
        # Claim initial job with pre-start abort guard
        try:
            job = call_api(f"/internal/claim/{JOB_ID}")
        except ControlAbort:
            log_state(JOB_ID, "aborted_before_start")
            sys.exit(0)

        if not job or not job.get("job_id"):
            log_state(JOB_ID, "claim_failed")
            sys.exit(1)

        if job.get("status") == "aborted" or job.get("control") in ("pause", "stop", "deleted"):
            log_state(JOB_ID, "aborted_before_start")
            sys.exit(0)

        log_state(JOB_ID, "claimed")
        mode = job.get("job_mode", "single")

        try:
            if mode == "batch_direct":
                execute_batch_direct(job, uploader)
            else:
                execute_single_download(job, uploader)
        except ControlAbort as ca:
            log_state(JOB_ID, ca.signal)
            abort_active_resources()
        except Exception:
            log_state(JOB_ID, "failed")
            abort_active_resources()

        # Continuous Multi-Queue Chaining + remainder-of-minute Warm-Tail
        while True:
            elapsed = time.monotonic() - RUNNER_START_TIME
            if elapsed >= 2280:  # 38 minutes max runner runtime
                break

            # Check if another queued job is waiting (0s boot delay chaining!)
            try:
                next_job = call_api("/internal/claim_next")
            except ControlAbort:
                break
            except Exception:
                break

            if next_job and next_job.get("job_id"):
                next_id = next_job["job_id"]
                log_state(next_id, "warm_claimed")
                next_mode = next_job.get("job_mode", "single")
                try:
                    if next_mode == "batch_direct":
                        execute_batch_direct(next_job, uploader)
                    else:
                        execute_single_download(next_job, uploader)
                except ControlAbort as ca:
                    log_state(next_id, ca.signal)
                    abort_active_resources()
                except Exception:
                    log_state(next_id, "failed")
                    abort_active_resources()
                continue

            # Free remainder-of-minute warm-tail
            elapsed = time.monotonic() - RUNNER_START_TIME
            rem = 60.0 - (elapsed % 60.0)
            if rem < 8.0:
                break
            time.sleep(3.0)

        log_state(JOB_ID, "finished")

    except ControlAbort as ca:
        log_state(JOB_ID, ca.signal)
        abort_active_resources()
        shutil.rmtree(f"/tmp/drivegrab/{JOB_ID}", ignore_errors=True)
        sys.exit(0)
    except Exception:
        abort_active_resources()
        shutil.rmtree(f"/tmp/drivegrab/{JOB_ID}", ignore_errors=True)
        sys.exit(1)
    finally:
        # Goodbye notification to Edge so warm timer resets immediately
        try:
            req = urllib.request.Request(
                f"{WORKER_URL}/internal/runner_goodbye",
                data=b"{}",
                headers={
                    "X-API-Key": API_SECRET,
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0"
                },
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as _:
                pass
        except Exception:
            pass


if __name__ == "__main__":
    main()
