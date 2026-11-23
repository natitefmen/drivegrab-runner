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
import threading
import collections
import base64
from typing import Optional, List, Dict, Any, Tuple

# Configuration
JOB_ID = os.environ.get("JOB_ID", "").strip()
WORKER_URL = os.environ.get("WORKER_URL", "").strip().rstrip("/")
API_SECRET = os.environ.get("API_SECRET", "").strip()

GDRIVE_CLIENT_ID = os.environ.get("GDRIVE_CLIENT_ID", "").strip()
GDRIVE_CLIENT_SECRET = os.environ.get("GDRIVE_CLIENT_SECRET", "").strip()
GDRIVE_REFRESH_TOKEN = os.environ.get("GDRIVE_REFRESH_TOKEN", "").strip()

CHUNK_SIZE = 32 * 1024 * 1024  # 32 MiB (33,554,432 bytes, exact multiple of 256 KiB)
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


def validate_public_url(url_str: str) -> bool:
    return is_ssrf_safe_url(url_str)


def is_cyberdrop_supported_host(url: str) -> bool:
    if not url:
        return False
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        patterns = (
            "bunkr.", "bunkrr.", "cyberdrop.", "gofile.io", "pixeldrain.com",
            "saint.", "saint2.", "coomer.", "kemono.", "mediafire.com",
            "mega.nz", "jpg5.", "simpcity."
        )
        return any(p in host for p in patterns)
    except Exception:
        return False


def extract_root_host(url_str: str) -> str:
    try:
        host = urllib.parse.urlparse(url_str).hostname.lower()
        parts = host.split('.')
        if len(parts) <= 2:
            return host
        two_part_tlds = {'co', 'com', 'org', 'net', 'gov', 'edu'}
        if parts[-2] in two_part_tlds and len(parts) >= 3:
            return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        return f"{parts[-2]}.{parts[-1]}"
    except Exception:
        return "unknown"


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


def format_size(bytes_val: int) -> str:
    if bytes_val <= 0:
        return ""
    if bytes_val < 1024 * 1024:
        return f"{(bytes_val / 1024):.1f} KB"
    if bytes_val < 1024 * 1024 * 1024:
        return f"{(bytes_val / (1024 * 1024)):.1f} MB"
    return f"{(bytes_val / (1024 * 1024 * 1024)):.2f} GB"


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

    # Cooperative control signal check
    control = res_data.get("control", "")
    if control in ("pause", "stop", "deleted"):
        raise ControlAbort(control)

    return res_data


def report_host_cooldown(host: str, seconds: int = 60, reason: str = "") -> None:
    try:
        call_api("/internal/host_cooldown", {
            "host": host,
            "seconds": seconds,
            "reason": reason
        })
    except Exception:
        pass


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
            except Exception:
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
                chunk_start = time.monotonic()
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

                            # Probe session offset
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

                chunk_elapsed = max(0.001, time.monotonic() - chunk_start)
                speed_bps = chunk_len / chunk_elapsed
                if speed_bps >= 1024 * 1024:
                    speed_text = f"{(speed_bps / (1024 * 1024)):.1f} MB/s"
                else:
                    speed_text = f"{(speed_bps / 1024):.0f} KB/s"

                now = time.monotonic()
                if (now - last_report >= 1.0) or (offset >= file_size):
                    last_report = now
                    pct = min(99.0, (offset / max(1, file_size)) * 100.0)
                    if on_progress:
                        try:
                            on_progress(pct, offset, file_size, speed_text)
                        except TypeError:
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
        proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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


def _parse_size_bytes(val_str: str, unit_str: str) -> int:
    try:
        val = float(val_str)
        u = unit_str.upper().strip()
        if "G" in u:
            return int(val * 1024 * 1024 * 1024)
        if "M" in u:
            return int(val * 1024 * 1024)
        if "K" in u:
            return int(val * 1024)
        return int(val)
    except Exception:
        return 0


def parse_dg_progress_line(line: str) -> Optional[Dict[str, Any]]:
    if not line:
        return None
    line_clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line).strip()
    if "DG_PROG|" in line_clean:
        idx = line_clean.find("DG_PROG|")
        rest = line_clean[idx + len("DG_PROG|"):]
        parts = rest.split("|")
        if len(parts) >= 7:
            pct_str, dl_b_str, tot_b_str, tot_est_str, frag_idx_str, frag_cnt_str, spd_str = [p.strip() for p in parts[:7]]

            dl_bytes = int(dl_b_str) if dl_b_str.isdigit() else 0
            tot_bytes = int(tot_b_str) if tot_b_str.isdigit() else (int(tot_est_str) if tot_est_str.isdigit() else 0)

            dl_pct = 0.0
            pct_clean = pct_str.replace("%", "").strip()
            try:
                dl_pct = float(pct_clean)
            except ValueError:
                if dl_bytes > 0 and tot_bytes > 0:
                    dl_pct = (dl_bytes / tot_bytes) * 100.0
                elif frag_idx_str.isdigit() and frag_cnt_str.isdigit() and int(frag_cnt_str) > 0:
                    dl_pct = (int(frag_idx_str) / int(frag_cnt_str)) * 100.0

            speed_text = ""
            if spd_str and spd_str.upper() not in ("NA", "UNKNOWN", "N/A"):
                m_spd = re.search(r'([\d\.]+)\s*([KMG]i?B)/s', spd_str, re.IGNORECASE)
                if m_spd:
                    val = m_spd.group(1)
                    unit = m_spd.group(2).upper().replace("I", "")
                    speed_text = f"{val} {unit}/s"
                else:
                    speed_text = spd_str.replace("MiB/s", " MB/s").replace("KiB/s", " KB/s").replace("GiB/s", " GB/s").strip()

            return {
                "dl_pct": min(100.0, max(0.0, dl_pct)),
                "downloaded_bytes": dl_bytes,
                "total_bytes": tot_bytes,
                "speed_text": speed_text
            }

    # aria2c console progress line: [#abc123 64MiB/250MiB(25%) CN:16 DL:18.4MiB]
    m_aria = re.search(
        r'\[#[0-9a-fA-F]+\s+([\d\.]+)\s*([A-Za-z]+)/([\d\.]+)\s*([A-Za-z]+)\((\d+(?:\.\d+)?)%\)(?:.*?DL:([\d\.]+)\s*([A-Za-z/]+))?',
        line_clean
    )
    if not m_aria:
        m_aria = re.search(
            r'([\d\.]+)\s*([A-Za-z]+)/([\d\.]+)\s*([A-Za-z]+)\((\d+(?:\.\d+)?)%\).*?DL:([\d\.]+)\s*([A-Za-z/]+)',
            line_clean
        )
    if m_aria:
        dl_val, dl_unit, tot_val, tot_unit, pct_str, spd_val, spd_unit = m_aria.groups()
        dl_bytes = _parse_size_bytes(dl_val, dl_unit)
        tot_bytes = _parse_size_bytes(tot_val, tot_unit)
        try:
            dl_pct = float(pct_str)
        except Exception:
            dl_pct = 0.0
        speed_text = ""
        if spd_val and spd_unit:
            u_clean = spd_unit.upper().replace("/S", "").replace("I", "").strip()
            speed_text = f"{spd_val} {u_clean}/s"
        return {
            "dl_pct": min(100.0, max(0.0, dl_pct)),
            "downloaded_bytes": dl_bytes,
            "total_bytes": tot_bytes,
            "speed_text": speed_text
        }

    m = re.search(r'\[download\]\s+([\d\.]+)%\s+of\s+~?([\d\.]+\s*[KMG]i?B)(?:\s+at\s+([\d\.]+\s*[KMG]i?B/s))?', line_clean)
    if m:
        try:
            dl_pct = float(m.group(1))
            spd = m.group(3) or ""
            speed_text = ""
            if spd:
                m_spd = re.search(r'([\d\.]+)\s*([KMG]i?B)/s', spd, re.IGNORECASE)
                if m_spd:
                    val = m_spd.group(1)
                    unit = m_spd.group(2).upper().replace("I", "")
                    speed_text = f"{val} {unit}/s"
                else:
                    speed_text = spd.replace("MiB/s", " MB/s").replace("KiB/s", " KB/s").replace("GiB/s", " GB/s").strip()
            return {
                "dl_pct": min(100.0, max(0.0, dl_pct)),
                "downloaded_bytes": 0,
                "total_bytes": 0,
                "speed_text": speed_text
            }
        except Exception:
            pass

    return None


def _clear_job_dir(job_dir: str) -> None:
    """Removes all files and subdirectories inside job_dir while preserving job_dir itself."""
    if not os.path.exists(job_dir):
        os.makedirs(job_dir, exist_ok=True)
        return
    for item in os.listdir(job_dir):
        item_path = os.path.join(job_dir, item)
        try:
            if os.path.isdir(item_path) and not os.path.islink(item_path):
                shutil.rmtree(item_path, ignore_errors=True)
            else:
                os.remove(item_path)
        except Exception:
            pass
    os.makedirs(job_dir, exist_ok=True)


def build_ytdlp_cmd(
    target_url: str,
    job_dir: str,
    out_tmpl: str,
    target_height: int = 1080,
    user_agent: Optional[str] = None,
    referer: Optional[str] = None,
    cookies: Optional[str] = None,
    use_aria2: bool = True,
    impersonate: Optional[str] = None,
    aria2_conns: int = 16,
) -> List[str]:
    format_spec = f"bv*[height<={target_height}][ext=mp4]+ba[ext=m4a]/b[height<={target_height}][ext=mp4]/bv*[height<={target_height}]+ba/b[height<={target_height}]/best"
    cmd = [
        sys.executable, "-m", "yt_dlp",
        "-f", format_spec,
        "--no-playlist",
        "--socket-timeout", "25",
        "--force-ipv4",
        "--abort-on-unavailable-fragments",
        "--concurrent-fragments", "24",
        "--fragment-retries", "15",
        "--retries", "15",
        "--newline",
        "--progress-template", "download:DG_PROG|%(progress._percent_str)s|%(progress.downloaded_bytes)s|%(progress.total_bytes)s|%(progress.total_bytes_estimate)s|%(progress.fragment_index)s|%(progress.fragment_count)s|%(progress._speed_str)s",
        "--merge-output-format", "mp4",
        "-P", job_dir,
        "-o", out_tmpl,
    ]

    parsed_path = (urllib.parse.urlparse(target_url).path or "").lower()
    url_low = target_url.lower()
    is_manifest = parsed_path.endswith((".m3u8", ".m3u", ".mpd"))
    is_tokenized_php = (
        parsed_path.endswith(".php")
        or "acctoken=" in url_low
        or "download=true" in url_low
        or "/get_file/" in parsed_path
    )

    if use_aria2 and aria2_conns > 1 and not is_manifest and not is_tokenized_php and shutil.which("aria2c"):
        conns = str(max(2, min(16, int(aria2_conns))))
        cmd.extend([
            "--downloader", "http:aria2c",
            "--downloader", "https:aria2c",
            "--downloader-args", f"aria2c:-x {conns} -s {conns} -k 1M --disable-ipv6=true --file-allocation=none --connect-timeout=20 --timeout=30 --max-tries=5 --retry-wait=2 --show-console-readout=true --summary-interval=1"
        ])

    if impersonate:
        cmd.extend(["--impersonate", impersonate])
    elif user_agent:
        cmd.extend(["--user-agent", user_agent])

    if referer:
        cmd.extend(["--add-header", f"Referer:{referer}"])
    if cookies:
        cmd.extend(["--add-header", f"Cookie:{cookies}"])

    cmd.extend(["--", target_url])
    return cmd


def run_process_with_heartbeat(
    cmd: List[str],
    job_id: str,
    phase_detail: str,
    timeout_sec: float = 2100.0,
    heartbeat_interval: float = 1.5,
    stall_timeout_sec: Optional[float] = 120.0,
    watch_dir: Optional[str] = None
) -> Tuple[int, str]:
    global _CURRENT_SUBPROC

    env = os.environ.copy()
    env.update({"TERM": "dumb", "NO_COLOR": "1", "CI": "1"})

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        bufsize=1,
        env=env
    )
    _CURRENT_SUBPROC = proc

    tail_lines: collections.deque = collections.deque(maxlen=40)
    latest_prog: Dict[str, Any] = {}
    prog_lock = threading.Lock()

    last_activity = time.monotonic()
    last_reported_dl_bytes = 0
    last_reported_dl_pct = 0.0

    def get_watch_dir_bytes(wdir: Optional[str]) -> int:
        if not wdir or not os.path.isdir(wdir):
            return 0
        total = 0
        try:
            for entry in os.scandir(wdir):
                if entry.is_file(follow_symlinks=False):
                    try:
                        total += entry.stat().st_size
                    except OSError:
                        pass
        except OSError:
            pass
        return total

    last_disk_bytes = get_watch_dir_bytes(watch_dir)

    def reader():
        nonlocal last_activity, last_reported_dl_bytes, last_reported_dl_pct
        try:
            if proc.stdout:
                for line in proc.stdout:
                    line_str = line.strip()
                    if not line_str:
                        continue
                    tail_lines.append(line_str)
                    prog = parse_dg_progress_line(line_str)
                    if prog:
                        with prog_lock:
                            latest_prog.update(prog)
                            dl_b = prog.get("downloaded_bytes", 0)
                            dl_p = prog.get("dl_pct", 0.0)
                            if dl_b > last_reported_dl_bytes or dl_p > last_reported_dl_pct:
                                last_reported_dl_bytes = max(last_reported_dl_bytes, dl_b)
                                last_reported_dl_pct = max(last_reported_dl_pct, dl_p)
                                last_activity = time.monotonic()
                    else:
                        with prog_lock:
                            if latest_prog.get("downloaded_bytes", 0) == 0:
                                last_activity = time.monotonic()
        except Exception:
            pass

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    last_hb = time.monotonic()
    start_time = time.monotonic()

    try:
        while proc.poll() is None:
            time.sleep(0.3)
            now = time.monotonic()

            if watch_dir:
                cur_disk_bytes = get_watch_dir_bytes(watch_dir)
                if cur_disk_bytes > last_disk_bytes:
                    last_disk_bytes = cur_disk_bytes
                    last_activity = now

            if stall_timeout_sec is not None and (now - last_activity > stall_timeout_sec):
                proc.kill()
                _CURRENT_SUBPROC = None
                t.join(timeout=2.0)
                stderr_text = "\n".join(tail_lines)
                return 124, stderr_text + "\nProcess stalled with no progress"

            if now - start_time > timeout_sec:
                proc.kill()
                _CURRENT_SUBPROC = None
                raise RuntimeError(f"Process timed out after {timeout_sec}s")

            if now - last_hb >= heartbeat_interval:
                last_hb = now
                with prog_lock:
                    cur_prog = dict(latest_prog)

                dl_pct = cur_prog.get("dl_pct", 0.0)
                overall_prog = min(99.0, max(0.0, dl_pct))

                update_payload: Dict[str, Any] = {
                    "progress": overall_prog,
                    "phase_detail": "Downloading" if dl_pct > 0 else phase_detail
                }
                if cur_prog.get("downloaded_bytes"):
                    update_payload["downloaded_bytes"] = cur_prog["downloaded_bytes"]
                if cur_prog.get("total_bytes"):
                    update_payload["total_bytes"] = cur_prog["total_bytes"]
                if cur_prog.get("speed_text"):
                    update_payload["speed_text"] = cur_prog["speed_text"]

                call_api(f"/internal/update/{job_id}", update_payload)

    except ControlAbort:
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=2.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        _CURRENT_SUBPROC = None
        raise
    finally:
        _CURRENT_SUBPROC = None

    t.join(timeout=2.0)
    stderr_text = "\n".join(tail_lines)
    return proc.returncode, stderr_text


def extract_archive_zipslip_safe(
    archive_path: str,
    extracted_dir: str,
    passwords: Optional[List[str]] = None,
    skip_junk: bool = True
) -> List[str]:
    """Extract archive using 7z with strict Zip-Slip and symlink defense."""
    os.makedirs(extracted_dir, exist_ok=True)
    seven_z = shutil.which("7z") or shutil.which("7za") or "7z"

    all_passwords = [""] + (passwords or [])
    success = False

    for pw in all_passwords:
        cmd = [seven_z, "x", "-y", f"-o{extracted_dir}"]
        if pw:
            cmd.append(f"-p{pw}")
        else:
            cmd.append("-p")
        cmd.append(archive_path)

        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode == 0:
            success = True
            break

    if not success:
        raise RuntimeError("Archive extraction failed (unsupported format or password required)")

    # Zip-Slip and Symlink Defense
    extracted_root = pathlib.Path(extracted_dir).resolve()
    valid_files: List[str] = []

    junk_extensions = {".nfo", ".url", ".txt", ".sfv", ".diz", ".db"}
    junk_names = {"thumbs.db", ".ds_store"}

    for p in list(pathlib.Path(extracted_dir).rglob("*")):
        try:
            # Reject symlinks unconditionally
            if p.is_symlink():
                p.unlink(missing_ok=True)
                continue

            # Zip-Slip directory traversal check
            resolved = p.resolve()
            if not str(resolved).startswith(str(extracted_root)):
                if p.is_file():
                    p.unlink(missing_ok=True)
                elif p.is_dir():
                    shutil.rmtree(str(p), ignore_errors=True)
                continue

            if p.is_file():
                # Junk filter
                if skip_junk:
                    ext = p.suffix.lower()
                    name = p.name.lower()
                    if ext in junk_extensions or name in junk_names or "__MACOSX" in str(p):
                        p.unlink(missing_ok=True)
                        continue
                valid_files.append(str(p))
        except Exception:
            pass

    return valid_files


def resolve_with_playwright(
    candidate_urls: List[str],
    page_url: str,
    cookies: str = "",
    user_agent: str = ""
) -> Optional[Dict[str, str]]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    valid_urls: List[str] = []
    seen = set()
    for u in (candidate_urls or []):
        if not u or not isinstance(u, str):
            continue
        u_clean = u.strip()
        if u_clean and u_clean not in seen and is_ssrf_safe_url(u_clean):
            seen.add(u_clean)
            valid_urls.append(u_clean)

    if not valid_urls:
        return None

    pw_instance = None
    browser = None
    context = None
    try:
        pw_instance = sync_playwright().start()
        chrome_path = os.getenv("PLAYWRIGHT_CHROME_PATH")
        if chrome_path and not os.path.exists(chrome_path):
            chrome_path = None

        launch_kwargs: Dict[str, Any] = {
            "headless": True,
            "args": ["--no-sandbox", "--disable-dev-shm-usage", "--autoplay-policy=no-user-gesture-required"]
        }
        if chrome_path:
            launch_kwargs["executable_path"] = chrome_path

        browser = pw_instance.chromium.launch(**launch_kwargs)

        ua = (
            user_agent
            if (user_agent and "Mozilla" in user_agent and "Mobile" not in user_agent)
            else "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )
        context = browser.new_context(
            user_agent=ua,
            viewport={"width": 1280, "height": 720},
            java_script_enabled=True
        )

        if cookies and page_url and is_ssrf_safe_url(page_url):
            cookie_list = []
            for part in cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    if k.strip():
                        cookie_list.append({
                            "name": k.strip(),
                            "value": v.strip(),
                            "url": page_url
                        })
            if cookie_list:
                try:
                    context.add_cookies(cookie_list)
                except Exception:
                    pass

        ad_hosts = (
            "doubleclick", "googlesyndication", "exoclick", "juicyads",
            "tsyndicate", "trafficjunky", "adtng", "popads", "adsterra",
            "popcash", "propellerads", "hilltopads", "clickadu", "monetag", "admaven"
        )
        dns_cache: Dict[str, bool] = {}

        def handle_route(route):
            try:
                r_url = route.request.url
                p = urllib.parse.urlparse(r_url)
                if p.scheme not in ("http", "https"):
                    route.abort()
                    return
                h = (p.hostname or "").lower()
                if any(ad in h for ad in ad_hosts):
                    route.abort()
                    return
                if route.request.resource_type in ("image", "font"):
                    route.abort()
                    return
                path_low = p.path.lower()
                if any(path_low.endswith(ext) for ext in (".ts", ".m4s", ".cmfv", ".cmfa")):
                    route.abort()
                    return
                if h not in dns_cache:
                    dns_cache[h] = is_ssrf_safe_url(r_url)
                if not dns_cache[h]:
                    route.abort()
                    return
                route.continue_()
            except Exception:
                try:
                    route.abort()
                except Exception:
                    pass

        context.route("**/*", handle_route)

        found_streams: List[Dict[str, Any]] = []

        def check_stream(u_target: str, status: Optional[int], headers: Optional[Dict[str, str]]):
            if not u_target:
                return
            t_low = u_target.lower()
            is_master = "master.m3u8" in t_low
            is_hls = ".m3u8" in t_low
            is_dash = ".mpd" in t_low
            ct = (headers.get("content-type") if headers else "") or ""
            ct_low = ct.lower()
            is_direct_media = (
                any(t_low.endswith(ext) or (f"{ext}?" in t_low) for ext in (".mp4", ".webm", ".mkv", ".mov", ".m4v"))
                or ("video/" in ct_low and "video/mp2t" not in ct_low)
            )

            if is_master or is_hls or is_dash or is_direct_media:
                if is_master and status in (200, 206):
                    prio = 0
                elif is_hls and status in (200, 206):
                    prio = 1
                elif is_hls:
                    prio = 2
                elif is_dash and status in (200, 206):
                    prio = 3
                elif is_dash:
                    prio = 4
                elif is_direct_media and status in (200, 206):
                    prio = 5
                else:
                    prio = 6

                found_streams.append({
                    "url": u_target,
                    "prio": prio,
                    "status": status,
                    "headers": headers or {}
                })

        def on_response(resp):
            try:
                check_stream(resp.url, resp.status, resp.headers)
            except Exception:
                pass

        def on_request(req):
            try:
                check_stream(req.url, None, req.headers)
            except Exception:
                pass

        context.on("response", on_response)
        context.on("request", on_request)

        page = context.new_page()
        start_time = time.monotonic()

        for cand_url in valid_urls[:2]:
            if time.monotonic() - start_time >= 30.0:
                break
            try:
                page.goto(cand_url, wait_until="domcontentloaded", timeout=20000)
            except Exception:
                pass

            wait_until_t = min(start_time + 32.0, time.monotonic() + 4.0)
            while time.monotonic() < wait_until_t:
                if any(s["prio"] <= 1 for s in found_streams):
                    break
                time.sleep(0.5)

            if not any(s["prio"] <= 5 for s in found_streams) and time.monotonic() - start_time < 28.0:
                for sel in ("video", '[class*="play"]', 'button[aria-label*="Play"]'):
                    try:
                        loc = page.locator(sel).first
                        if loc.is_visible(timeout=1000):
                            loc.click(timeout=1500)
                            break
                    except Exception:
                        pass
                wait_until_click = min(start_time + 34.0, time.monotonic() + 6.0)
                while time.monotonic() < wait_until_click:
                    if any(s["prio"] <= 1 for s in found_streams):
                        break
                    time.sleep(0.5)

            if not found_streams:
                try:
                    src_val = page.locator('video source[src], video[src]').first.get_attribute('src')
                    if src_val and src_val.startswith(("http://", "https://")) and is_ssrf_safe_url(src_val):
                        check_stream(src_val, 200, {})
                except Exception:
                    pass

            if found_streams:
                break

        if not found_streams:
            return None

        found_streams.sort(key=lambda x: (x["prio"], -(1 if x["status"] in (200, 206) else 0)))
        best = found_streams[0]
        stream_url = best["url"]

        captured_cookies = ""
        try:
            c_objs = context.cookies(stream_url)
            captured_cookies = "; ".join(f"{c['name']}={c['value']}" for c in c_objs if 'name' in c and 'value' in c)
        except Exception:
            pass

        ref = page.url or page_url
        orig = ""
        try:
            p_ref = urllib.parse.urlparse(ref)
            orig = f"{p_ref.scheme}://{p_ref.netloc}"
        except Exception:
            pass

        return {
            "url": stream_url,
            "referer": ref,
            "origin": orig,
            "user_agent": ua,
            "cookies": captured_cookies
        }

    except Exception:
        return None
    finally:
        if context:
            try:
                context.close()
            except Exception:
                pass
        if browser:
            try:
                browser.close()
            except Exception:
                pass
        if pw_instance:
            try:
                pw_instance.stop()
            except Exception:
                pass


def execute_linkgrabber_analyze(job: Dict[str, Any]) -> None:
    job_id = job["job_id"]
    log_state(job_id, "analyzing")
    call_api(f"/internal/update/{job_id}", {
        "status": "downloading",
        "phase_detail": "Analyzing links with cloud plugins..."
    })

    payload_str = job.get("batch_payload", "{}")
    payload = json.loads(payload_str) if payload_str else {}
    staged_id = payload.get("staged_id") or job_id
    urls = payload.get("urls") or [job.get("url")]
    page_url = payload.get("page_url") or job.get("page_url")
    cookies = payload.get("cookies")
    user_agent = payload.get("user_agent")
    deep_analyze = payload.get("deep_analyze", False)

    first_url = urls[0] if urls else (page_url or "")
    root_host = extract_root_host(first_url)
    items: List[Dict[str, Any]] = []
    plugin_used = "direct"
    detected_title = f"{root_host} Album"

    for u in urls[:40]:
        if not u or not is_ssrf_safe_url(u):
            continue

        u_low = u.lower()
        # Playlist or Video platform
        if any(v in u_low for v in ("youtube.com", "youtu.be", "vimeo.com", "tiktok.com", "x.com", "twitter.com", "tnaflix.com", "spankbang.com", "pornhub.com")):
            plugin_used = "yt-dlp"
            cmd = [
                sys.executable, "-m", "yt_dlp",
                "--flat-playlist",
                "--dump-single-json",
                "--socket-timeout", "20",
                "--playlist-end", "40",
            ]
            if user_agent:
                cmd.extend(["--user-agent", user_agent])
            if cookies:
                cmd.extend(["--add-header", f"Cookie:{cookies}"])
            cmd.extend(["--", u])

            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode == 0 and res.stdout:
                    info = json.loads(res.stdout)
                    detected_title = info.get("title") or detected_title
                    entries = info.get("entries") or [info]
                    for idx, e in enumerate(entries):
                        if not e:
                            continue
                        e_url = e.get("url") or e.get("webpage_url") or u
                        if not e_url.startswith("http"):
                            e_url = f"https://www.youtube.com/watch?v={e_url}"
                        items.append({
                            "url": e_url,
                            "title": e.get("title") or f"Video {idx + 1}",
                            "filename": f"{sanitize_filename(e.get('title') or f'Video_{idx + 1}')}.mp4",
                            "size_bytes": e.get("filesize") or e.get("filesize_approx") or 0,
                            "size_text": format_size(e.get("filesize") or e.get("filesize_approx") or 0),
                            "file_type": "video",
                            "availability": "online",
                            "item_kind": "watch_page",
                            "duration_text": str(e.get("duration") or ""),
                        })
                    continue
            except Exception:
                pass

        # Cyberdrop / Gallery / File host
        cyberdrop_bin = shutil.which("cyberdrop-dl") or str(pathlib.Path(sys.executable).parent / "cyberdrop-dl")
        gallery_dl_bin = shutil.which("gallery-dl") or str(pathlib.Path(sys.executable).parent / "gallery-dl")

        if os.path.exists(gallery_dl_bin) and any(g in u_low for g in ("kemono", "coomer", "e-hentai", "danbooru", "imgbox")):
            plugin_used = "gallery-dl"
            g_cmd = [gallery_dl_bin, "--dump-json", "--range", "1-60", u]
            try:
                g_res = subprocess.run(g_cmd, capture_output=True, text=True, timeout=35)
                if g_res.returncode == 0 and g_res.stdout:
                    for line in g_res.stdout.splitlines():
                        if not line.strip():
                            continue
                        try:
                            g_data = json.loads(line)
                            if isinstance(g_data, list) and len(g_data) >= 2:
                                g_url = g_data[1]
                                g_meta = g_data[2] if len(g_data) >= 3 else {}
                                fn = g_meta.get("filename") or g_url.split("/")[-1].split("?")[0]
                                items.append({
                                    "url": g_url,
                                    "title": fn,
                                    "filename": fn,
                                    "size_bytes": 0,
                                    "size_text": "",
                                    "file_type": "image",
                                    "availability": "online",
                                    "item_kind": "direct_file",
                                    "duration_text": "",
                                })
                        except Exception:
                            pass
                    if items:
                        continue
            except Exception:
                pass

        # Direct file fallback
        raw_name = u.split("/")[-1].split("?")[0] or "file"
        ft = "video" if raw_name.lower().endswith((".mp4", ".mkv", ".webm")) else ("archive" if raw_name.lower().endswith((".zip", ".rar", ".7z")) else "other")
        items.append({
            "url": u,
            "title": raw_name,
            "filename": raw_name,
            "size_bytes": 0,
            "size_text": "",
            "file_type": ft,
            "availability": "online",
            "item_kind": "direct_file",
            "duration_text": "",
        })

    # Post structured results to Cloudflare Edge
    call_api(f"/internal/linkgrabber_result/{staged_id}", {
        "title": detected_title,
        "plugin": plugin_used,
        "source_host": root_host,
        "items": items,
    })

    log_state(job_id, "analyzed", f"count={len(items)}")
    call_api(f"/internal/update/{job_id}", {
        "status": "completed",
        "phase_detail": f"Analysis complete ({len(items)} items discovered)"
    })


ALLOWED_SIGN_HOSTS = [
    base64.b64decode(b'Y2RuLmNy').decode(),
    base64.b64decode(b'YnVua3IuY3I=').decode(),
    base64.b64decode(b'YnVua3IuaXM=').decode(),
    base64.b64decode(b'YnVua3Iuc2k=').decode(),
    base64.b64decode(b'YnVua3IudG8=').decode(),
    base64.b64decode(b'YnVua3JyLnN1').decode(),
]

_CYBERDROP_DIR_FLAG: Optional[str] = None


def _strip_media_ext(name: str) -> str:
    known = (
        ".mp4", ".mkv", ".webm", ".mov", ".m4v", ".ts",
        ".avi", ".flv", ".zip", ".rar", ".7z"
    )
    low = name.lower()
    for ext in known:
        if low.endswith(ext):
            return name[:-len(ext)]
    return name


_CYBERDROP_CLI_CONFIG: Optional[Dict[str, Any]] = None


def _probe_cyberdrop_cli(cyberdrop_bin: str) -> Dict[str, Any]:
    global _CYBERDROP_CLI_CONFIG
    if _CYBERDROP_CLI_CONFIG is not None:
        return _CYBERDROP_CLI_CONFIG

    config: Dict[str, Any] = {
        "has_download_subcmd": False,
        "dir_flag": "--download-folder",
        "has_appdata_flag": False,
        "has_ui_flag": False,
    }

    try:
        res = subprocess.run(
            [cyberdrop_bin, "download", "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        help_text = (res.stdout or "") + (res.stderr or "")
        if res.returncode == 0 and any(flag in help_text for flag in ("--download-folder", "-d", "-o")):
            config["has_download_subcmd"] = True
            if "--download-folder" in help_text:
                config["dir_flag"] = "--download-folder"
            elif "-d" in help_text:
                config["dir_flag"] = "-d"
            elif "-o" in help_text:
                config["dir_flag"] = "-o"
            config["has_appdata_flag"] = "--appdata-folder" in help_text
            config["has_ui_flag"] = "--ui" in help_text
            _CYBERDROP_CLI_CONFIG = config
            return config
    except Exception:
        pass

    try:
        res = subprocess.run(
            [cyberdrop_bin, "--help"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )
        help_text = (res.stdout or "") + (res.stderr or "")
        if "--download-folder" in help_text:
            config["dir_flag"] = "--download-folder"
        elif "-d" in help_text:
            config["dir_flag"] = "-d"
        elif "-o" in help_text:
            config["dir_flag"] = "-o"
        config["has_appdata_flag"] = "--appdata-folder" in help_text
        config["has_ui_flag"] = "--ui" in help_text
    except Exception:
        pass

    _CYBERDROP_CLI_CONFIG = config
    return config


def _build_cyberdrop_cmd(
    cyberdrop_bin: str,
    job_dir: str,
    appdata_dir: str,
    raw_url: str
) -> List[str]:
    cfg = _probe_cyberdrop_cli(cyberdrop_bin)
    cmd: List[str] = [cyberdrop_bin]
    if cfg["has_download_subcmd"]:
        cmd.append("download")

    cmd.extend([cfg["dir_flag"], job_dir])

    if cfg["has_appdata_flag"]:
        os.makedirs(appdata_dir, exist_ok=True)
        cmd.extend(["--appdata-folder", appdata_dir])

    if cfg["has_ui_flag"]:
        cmd.extend(["--ui", "disabled"])

    cmd.append(raw_url)
    return cmd


def resolve_signed_media_item(
    item_url: str,
    cookies: str = "",
    user_agent: str = ""
) -> Optional[Dict[str, Any]]:
    if not is_ssrf_safe_url(item_url):
        return None

    ua = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    headers = {
        "User-Agent": ua,
        "Referer": item_url
    }
    if cookies:
        headers["Cookie"] = cookies

    page_html = ""
    for attempt in range(3):
        try:
            from curl_cffi import requests as cffi_requests
            resp = cffi_requests.get(item_url, headers=headers, impersonate="chrome", timeout=20)
            if resp.status_code == 200:
                page_html = resp.text
                break
            elif resp.status_code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(1.5 if attempt == 0 else 3.0)
                continue
        except Exception:
            if attempt < 2:
                time.sleep(1.5 if attempt == 0 else 3.0)
                continue
            page_html = ""

    if not page_html:
        for attempt in range(2):
            try:
                req = urllib.request.Request(item_url, headers=headers)
                with urllib.request.urlopen(req, timeout=20) as u_resp:
                    if u_resp.status == 200:
                        page_html = u_resp.read().decode("utf-8", errors="replace")
                        break
                    elif u_resp.status in (429, 502, 503, 504) and attempt < 1:
                        time.sleep(1.5)
                        continue
            except urllib.error.HTTPError as he:
                if he.code in (429, 502, 503, 504) and attempt < 1:
                    time.sleep(1.5)
                    continue
                return None
            except Exception:
                if attempt < 1:
                    time.sleep(1.5)
                    continue
                return None

    if not page_html:
        return None

    body_low = page_html[:8000].lower()
    if "unavailable for maintenance" in body_low or "maintenance is in progress" in body_low:
        return {"is_maintenance": True}

    m_cdn = re.search(r'jsCDN\s*=\s*["\']([^"\']+)["\']', page_html)
    m_sign = re.search(r'signUrl\s*=\s*["\']([^"\']+)["\']', page_html)

    if not m_cdn or not m_sign:
        # Check direct media links in HTML (<source> or <video>)
        m_src = re.search(
            r'<(?:source|video)[^>]+src=["\'](https?://[^"\']+\.(?:mp4|mkv|webm|mov|m4v)(?:\?[^"\']*)?)["\']',
            page_html,
            re.IGNORECASE
        )
        if m_src:
            direct_url = m_src.group(1).replace(r"\/", "/")
            if is_ssrf_safe_url(direct_url):
                extracted_name = ""
                m_h1 = re.search(r'<h1[^>]*>([^<]+)</h1>', page_html, re.IGNORECASE)
                if m_h1:
                    extracted_name = m_h1.group(1).strip()
                if not extracted_name:
                    m_title = re.search(r'<title[^>]*>([^<]+)</title>', page_html, re.IGNORECASE)
                    if m_title:
                        extracted_name = m_title.group(1).strip()
                if not extracted_name:
                    extracted_name = os.path.basename(urllib.parse.urlparse(direct_url).path)
                return {
                    "url": direct_url,
                    "filename": extracted_name,
                    "referer": item_url
                }
        return None

    js_cdn = m_cdn.group(1).replace(r"\/", "/")
    sign_url = m_sign.group(1).replace(r"\/", "/")

    parsed_sign = urllib.parse.urlparse(sign_url)
    if parsed_sign.scheme != "https" or not is_ssrf_safe_url(sign_url):
        return None

    sign_host = (parsed_sign.hostname or "").lower()
    is_valid_sign = (
        sign_host == "cdn.cr"
        or sign_host.endswith(".cdn.cr")
        or bool(re.match(r"^([a-z0-9-]+\.)*bunkrr?\.[a-z]{2,6}$", sign_host))
    )
    if not is_valid_sign:
        return None

    parsed_cdn = urllib.parse.urlparse(js_cdn)
    if not is_ssrf_safe_url(js_cdn):
        return None

    cdn_path = parsed_cdn.path
    sign_req_url = f"{sign_url}?path={urllib.parse.quote(cdn_path)}"
    if not is_ssrf_safe_url(sign_req_url):
        return None

    sign_json: Dict[str, Any] = {}
    for attempt in range(3):
        try:
            from curl_cffi import requests as cffi_requests
            s_resp = cffi_requests.get(sign_req_url, headers=headers, impersonate="chrome", timeout=20)
            if s_resp.status_code == 200:
                sign_json = s_resp.json()
                break
            elif s_resp.status_code in (429, 502, 503, 504) and attempt < 2:
                time.sleep(1.5 if attempt == 0 else 3.0)
                continue
        except Exception:
            if attempt < 2:
                time.sleep(1.5 if attempt == 0 else 3.0)
                continue
            sign_json = {}

    if not sign_json:
        for attempt in range(2):
            try:
                req_sign = urllib.request.Request(sign_req_url, headers=headers)
                with urllib.request.urlopen(req_sign, timeout=20) as s_resp2:
                    if s_resp2.status == 200:
                        sign_json = json.loads(s_resp2.read().decode("utf-8", errors="replace"))
                        break
                    elif s_resp2.status in (429, 502, 503, 504) and attempt < 1:
                        time.sleep(1.5)
                        continue
            except urllib.error.HTTPError as he:
                if he.code in (429, 502, 503, 504) and attempt < 1:
                    time.sleep(1.5)
                    continue
                return None
            except Exception:
                if attempt < 1:
                    time.sleep(1.5)
                    continue
                return None

    token = sign_json.get("token")
    ex = sign_json.get("ex")
    if not token or not ex:
        return None

    q_dict = dict(urllib.parse.parse_qsl(parsed_cdn.query))
    q_dict["token"] = str(token)
    q_dict["ex"] = str(ex)
    final_query = urllib.parse.urlencode(q_dict)
    direct_cdn_url = urllib.parse.urlunparse((
        parsed_cdn.scheme,
        parsed_cdn.netloc,
        parsed_cdn.path,
        parsed_cdn.params,
        final_query,
        parsed_cdn.fragment
    ))

    extracted_name = ""
    m_h1 = re.search(r'<h1[^>]*>([^<]+)</h1>', page_html, re.IGNORECASE)
    if m_h1:
        extracted_name = m_h1.group(1).strip()
    if not extracted_name:
        m_title = re.search(r'<title[^>]*>([^<]+)</title>', page_html, re.IGNORECASE)
        if m_title:
            extracted_name = m_title.group(1).strip()
    if not extracted_name:
        extracted_name = os.path.basename(parsed_cdn.path)

    return {
        "url": direct_cdn_url,
        "filename": extracted_name,
        "referer": item_url
    }


def download_direct_with_aria2_or_curl(
    url: str,
    job_dir: str,
    preferred_name: str,
    job_id: str,
    referer: Optional[str] = None,
    cookies: Optional[str] = None,
    user_agent: Optional[str] = None
) -> bool:
    valid_exts = (
        ".mp4", ".mkv", ".webm", ".mov", ".m4v", ".ts",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".jpg", ".jpeg", ".png", ".webp", ".gif",
        ".mp3", ".m4a", ".flac", ".wav",
        ".pdf", ".txt", ".json", ".csv"
    )
    parsed = urllib.parse.urlparse(url)
    cdn_fn = os.path.basename(parsed.path or "")
    cdn_ext = os.path.splitext(cdn_fn)[1].lower()

    target_fn = ""
    if preferred_name:
        sanitized_pref = sanitize_filename(preferred_name)
        if any(sanitized_pref.lower().endswith(ext) for ext in valid_exts):
            target_fn = sanitized_pref
        elif cdn_ext in valid_exts:
            target_fn = f"{sanitized_pref}{cdn_ext}"
        else:
            target_fn = sanitized_pref

    if not target_fn or not any(target_fn.lower().endswith(ext) for ext in valid_exts):
        if cdn_fn and any(cdn_fn.lower().endswith(ext) for ext in valid_exts):
            target_fn = sanitize_filename(cdn_fn)
        else:
            target_fn = f"media_{job_id[:8]}.mp4"

    ua = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

    aria2_bin = shutil.which("aria2c")
    if aria2_bin:
        # Step 1: 16 connections
        cmd_16 = [
            aria2_bin,
            "-x", "16",
            "-s", "16",
            "-k", "1M",
            "--disable-ipv6=true",
            "--max-tries=5",
            "--retry-wait=2",
            "--allow-overwrite=true",
            "--auto-file-renaming=false",
            "--file-allocation=none",
            "--connect-timeout=20",
            "--timeout=30",
            "--show-console-readout=true",
            "--summary-interval=1",
            "--dir", job_dir,
            "--out", target_fn,
            f"--user-agent={ua}"
        ]
        if referer:
            cmd_16.append(f"--header=Referer: {referer}")
        if cookies:
            cmd_16.append(f"--header=Cookie: {cookies}")
        cmd_16.append(url)

        ret, stderr_text = run_process_with_heartbeat(
            cmd_16, job_id, "Downloading directly via aria2c (16 conns)...",
            timeout_sec=2100.0, watch_dir=job_dir
        )
        target_path = pathlib.Path(job_dir) / target_fn
        if ret == 0 and target_path.is_file() and target_path.stat().st_size > 50 * 1024:
            return True

        # Step 2: Retry with 4 connections
        _clear_job_dir(job_dir)
        cmd_4 = [
            aria2_bin,
            "-x", "4",
            "-s", "4",
            "-k", "1M",
            "--disable-ipv6=true",
            "--max-tries=5",
            "--retry-wait=2",
            "--allow-overwrite=true",
            "--auto-file-renaming=false",
            "--file-allocation=none",
            "--connect-timeout=20",
            "--timeout=30",
            "--show-console-readout=true",
            "--summary-interval=1",
            "--dir", job_dir,
            "--out", target_fn,
            f"--user-agent={ua}"
        ]
        if referer:
            cmd_4.append(f"--header=Referer: {referer}")
        if cookies:
            cmd_4.append(f"--header=Cookie: {cookies}")
        cmd_4.append(url)

        ret4, stderr4 = run_process_with_heartbeat(
            cmd_4, job_id, "Downloading directly via aria2c (4 conns)...",
            timeout_sec=2100.0, watch_dir=job_dir
        )
        target_path = pathlib.Path(job_dir) / target_fn
        if ret4 == 0 and target_path.is_file() and target_path.stat().st_size > 50 * 1024:
            return True

    # Step 3: Clear job_dir before urllib fallback
    _clear_job_dir(job_dir)
    target_path = pathlib.Path(job_dir) / target_fn
    headers = {"User-Agent": ua}
    if referer:
        headers["Referer"] = referer
    if cookies:
        headers["Cookie"] = cookies

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=20) as resp:
            if resp.status == 200:
                tot_len = int(resp.headers.get("Content-Length", "0"))
                cd_header = resp.headers.get("Content-Disposition", "")
                if "filename=" in cd_header:
                    m_fn = re.search(r'filename=["\']?([^"\';\r\n]+)', cd_header)
                    if m_fn:
                        cd_fn = sanitize_filename(m_fn.group(1).strip())
                        if any(cd_fn.lower().endswith(ext) for ext in valid_exts):
                            target_fn = cd_fn
                            target_path = pathlib.Path(job_dir) / target_fn

                dl_bytes = 0
                last_hb_bytes = 0
                last_active = time.monotonic()
                last_hb = time.monotonic()
                with open(target_path, "wb") as out_f:
                    while True:
                        chunk = resp.read(64 * 1024)
                        if not chunk:
                            break
                        out_f.write(chunk)
                        dl_bytes += len(chunk)
                        last_active = time.monotonic()
                        now = time.monotonic()
                        if now - last_hb >= 1.5:
                            elapsed = max(0.001, now - last_hb)
                            bytes_diff = dl_bytes - last_hb_bytes
                            speed_bps = bytes_diff / elapsed
                            speed_text = f"{speed_bps / (1024 * 1024):.1f} MB/s" if speed_bps >= 1024 * 1024 else f"{speed_bps / 1024:.0f} KB/s"
                            last_hb = now
                            last_hb_bytes = dl_bytes

                            dl_pct = (dl_bytes / tot_len * 100.0) if tot_len > 0 else 0.0
                            call_api(f"/internal/update/{job_id}", {
                                "progress": min(99.0, max(0.0, dl_pct)),
                                "downloaded_bytes": dl_bytes,
                                "total_bytes": tot_len,
                                "speed_text": speed_text,
                                "phase_detail": "Downloading"
                            })
                        if time.monotonic() - last_active > 25:
                            raise TimeoutError("Stall watchdog triggered in streaming download")
                if target_path.is_file() and target_path.stat().st_size > 50 * 1024:
                    return True
    except Exception:
        pass

    return False


def is_valid_upload_candidate(
    file_path: pathlib.Path,
    plugin: str,
    expected_is_direct_doc: bool
) -> Tuple[bool, str]:
    if not file_path.is_file():
        return False, "Not a file"

    suffix_low = file_path.suffix.lower()

    forbidden_suffixes = {
        ".unknown_video", ".html", ".htm", ".xhtml", ".part",
        ".ytdl", ".tmp", ".log", ".db", ".sqlite", ".sqlite3",
        ".ini", ".cfg", ".yaml", ".yml", ".aria2"
    }
    if suffix_low in forbidden_suffixes:
        return False, f"Forbidden file extension: {suffix_low}"

    if not expected_is_direct_doc:
        doc_suffixes = {".txt", ".json", ".xml", ".csv"}
        if suffix_low in doc_suffixes:
            return False, f"Unexpected metadata/text file in media download: {suffix_low}"

    size = file_path.stat().st_size
    if size == 0:
        return False, "Zero-byte file"

    try:
        with open(file_path, "rb") as f:
            header = f.read(512).strip().lower()
            if (
                header.startswith(b"<!doc")
                or header.startswith(b"<html")
                or header.startswith(b"<head")
                or header.startswith(b"<script")
                or header.startswith(b"<?xml")
                or header.startswith(b'{"error')
            ):
                return False, "File content is HTML/XML/JSON error page instead of media"
    except Exception as e:
        return False, f"Could not inspect file header: {e}"

    video_exts = {".mp4", ".mkv", ".webm", ".mov", ".m4v", ".ts", ".avi", ".flv"}
    if suffix_low in video_exts or not expected_is_direct_doc:
        if size < 50 * 1024:
            return False, f"File size too small ({size} bytes < 50 KB minimum)"

    return True, ""


def valid_upload_candidates(
    job_dir: str,
    plugin: str,
    expected_is_direct_doc: bool
) -> List[pathlib.Path]:
    candidates = []
    for f in pathlib.Path(job_dir).rglob("*"):
        if f.is_file():
            ok, _ = is_valid_upload_candidate(f, plugin, expected_is_direct_doc)
            if ok:
                candidates.append(f)
    return candidates


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
    plugin = job.get("plugin", "direct")
    auto_extract = job.get("auto_extract", 0) == 1
    target_height = job.get("target_height") or 1080

    root_host = extract_root_host(raw_url)
    job_dir = f"/tmp/drivegrab/{job_id}"
    cdl_appdata_dir = f"/tmp/drivegrab/cdl_app_{job_id}"
    os.makedirs(job_dir, exist_ok=True)

    try:
        log_state(job_id, "downloading")
        call_api(f"/internal/update/{job_id}", {
            "status": "downloading",
            "phase_detail": "Connecting to CDN..."
        })

        safe_name = sanitize_filename(filename or title)
        safe_stem = _strip_media_ext(safe_name).replace("%", "%%")
        out_tmpl = f"{safe_stem}.%(ext)s" if safe_stem else "%(title)s.%(ext)s"

        success = False
        stderr_text = ""

        expected_is_direct_doc = (plugin == "direct") and (
            urllib.parse.urlparse(raw_url).path.lower().endswith(
                (".pdf", ".txt", ".json", ".csv", ".doc", ".docx", ".xls", ".xlsx", ".epub")
            )
        )

        is_crawled_item = plugin in ("webpage_crawl", "tube_grid", "ytdlp_playlist", "browser_batch")

        # 1. Cyberlocker / multi-file host lane
        if plugin == "cyberdrop-dl" or is_cyberdrop_supported_host(raw_url):
            parsed_raw = urllib.parse.urlparse(raw_url)
            is_item_page = any(parsed_raw.path.startswith(prefix) for prefix in ("/f/", "/v/"))

            # Step 1: Signed-media item page direct resolution
            if is_item_page:
                log_state(job_id, "resolving_signed_media")
                call_api(f"/internal/update/{job_id}", {
                    "phase_detail": "Resolving signed CDN direct media..."
                })
                resolved = resolve_signed_media_item(raw_url, cookies=cookies or "", user_agent=user_agent or "")
                if resolved and resolved.get("is_maintenance"):
                    raise RuntimeError("Host server is currently under maintenance")
                if resolved and resolved.get("url"):
                    direct_url = resolved["url"]
                    pref_name = resolved.get("filename") or safe_name
                    success = download_direct_with_aria2_or_curl(
                        direct_url, job_dir, pref_name, job_id,
                        referer=resolved.get("referer") or raw_url,
                        cookies=cookies, user_agent=user_agent
                    )

            # Step 2: Cyberdrop-dl invocation
            if not success:
                cyberdrop_bin = shutil.which("cyberdrop-dl") or str(pathlib.Path(sys.executable).parent / "cyberdrop-dl")
                cd_cmd = _build_cyberdrop_cmd(cyberdrop_bin, job_dir, cdl_appdata_dir, raw_url)
                ret, stderr_text = run_process_with_heartbeat(
                    cd_cmd, job_id, "Downloading via cyberdrop-dl...",
                    timeout_sec=900.0, watch_dir=job_dir
                )
                if "429" in stderr_text or "Too Many Requests" in stderr_text:
                    report_host_cooldown(root_host, 60, "Rate limited (429)")
                if ret == 0 and len(valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)) > 0:
                    success = True

            # Step 3: Playwright fallback for cyberlocker
            if not success:
                log_state(job_id, "resolving_stream")
                call_api(f"/internal/update/{job_id}", {
                    "phase_detail": "Resolving stream via headless browser..."
                })
                pw_stream = resolve_with_playwright([raw_url], raw_url, cookies or "", user_agent or "")
                if pw_stream and pw_stream.get("url"):
                    stream_url = pw_stream["url"]
                    pw_ref = pw_stream.get("referer") or raw_url
                    pw_cook = pw_stream.get("cookies") or cookies
                    pw_ua = pw_stream.get("user_agent") or user_agent
                    success = download_direct_with_aria2_or_curl(
                        stream_url, job_dir, safe_name, job_id,
                        referer=pw_ref, cookies=pw_cook, user_agent=pw_ua
                    )
                    if not success:
                        _clear_job_dir(job_dir)
                        cmd_pw = build_ytdlp_cmd(
                            stream_url, job_dir, out_tmpl, target_height, pw_ua, pw_ref, pw_cook,
                            use_aria2=True, aria2_conns=16
                        )
                        ret_pw, stderr_pw = run_process_with_heartbeat(
                            cmd_pw, job_id, "Downloading resolved stream...",
                            timeout_sec=900.0, watch_dir=job_dir
                        )
                        if ret_pw == 0 and len(valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)) > 0:
                            success = True
                        else:
                            stderr_text += f"\n{stderr_pw}"

            # Step 4: Strict Lane Separation - NEVER fall through to generic yt-dlp on cyberlocker item pages!
            if not success:
                raise RuntimeError("Could not resolve downloadable media from host page")

        elif plugin == "gallery-dl":
            gallery_dl_bin = shutil.which("gallery-dl") or str(pathlib.Path(sys.executable).parent / "gallery-dl")
            g_cmd = [gallery_dl_bin, "-d", job_dir, raw_url]
            ret, stderr_text = run_process_with_heartbeat(
                g_cmd, job_id, "Downloading via gallery-dl...",
                timeout_sec=900.0, watch_dir=job_dir
            )
            if "429" in stderr_text or "Too Many Requests" in stderr_text:
                report_host_cooldown(root_host, 60, "Rate limited (429)")
            if ret == 0 and len(valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)) > 0:
                success = True

        else:
            # Generic yt-dlp lane (with stepped aria2 connection ladder: 16 -> 4 -> 1)
            cmd = build_ytdlp_cmd(
                raw_url, job_dir, out_tmpl, target_height, user_agent, referer, cookies,
                use_aria2=True, aria2_conns=16
            )
            ret, stderr_text = run_process_with_heartbeat(
                cmd, job_id, "Downloading via yt-dlp...",
                timeout_sec=2100.0, watch_dir=job_dir
            )

            # Step 2: Retry with 4 connections if 16 connections failed
            if ret != 0 and "--downloader" in cmd:
                _clear_job_dir(job_dir)
                log_state(job_id, "retry_4_connections")
                call_api(f"/internal/update/{job_id}", {
                    "phase_detail": "Retrying with 4 connections..."
                })
                cmd_4 = build_ytdlp_cmd(
                    raw_url, job_dir, out_tmpl, target_height, user_agent, referer, cookies,
                    use_aria2=True, aria2_conns=4
                )
                ret, stderr_text = run_process_with_heartbeat(
                    cmd_4, job_id, "Downloading via yt-dlp (4 connections)...",
                    timeout_sec=2100.0, watch_dir=job_dir
                )

            # Step 3: Retry with single connection if aria2 was used and failed
            if ret != 0 and "--downloader" in cmd:
                _clear_job_dir(job_dir)
                log_state(job_id, "retry_single_connection")
                call_api(f"/internal/update/{job_id}", {
                    "phase_detail": "Retrying with standard connection..."
                })
                cmd_single = build_ytdlp_cmd(
                    raw_url, job_dir, out_tmpl, target_height, user_agent, referer, cookies,
                    use_aria2=False
                )
                ret, stderr_text = run_process_with_heartbeat(
                    cmd_single, job_id, "Downloading via yt-dlp (standard connection)...",
                    timeout_sec=2100.0, watch_dir=job_dir
                )

            if "429" in stderr_text or "Too Many Requests" in stderr_text:
                report_host_cooldown(root_host, 60, "Rate limited (429)")

            if ret == 0 and len(valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)) > 0:
                success = True

            # Fallback handling for crawled item vs sniffed CDN
            if not success:
                if is_crawled_item:
                    _clear_job_dir(job_dir)
                    log_state(job_id, "item_impersonate_fallback")
                    call_api(f"/internal/update/{job_id}", {
                        "phase_detail": "Resolving crawled item with browser impersonation..."
                    })
                    cmd_impersonate = build_ytdlp_cmd(
                        raw_url, job_dir, out_tmpl, target_height, None, referer, cookies,
                        use_aria2=True, impersonate="chrome", aria2_conns=16
                    )
                    ret_imp, stderr_imp = run_process_with_heartbeat(
                        cmd_impersonate, job_id, "Downloading item via browser impersonation...",
                        timeout_sec=900.0, watch_dir=job_dir
                    )
                    if ret_imp == 0 and len(valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)) > 0:
                        success = True
                    else:
                        stderr_text += f"\n{stderr_imp}"
                elif page_url and page_url != raw_url:
                    _clear_job_dir(job_dir)
                    log_state(job_id, "page_fallback")
                    call_api(f"/internal/update/{job_id}", {
                        "phase_detail": "CDN stalled — resolving via page extractor..."
                    })
                    cmd_fallback = build_ytdlp_cmd(
                        page_url, job_dir, out_tmpl, target_height, None, page_url, cookies,
                        use_aria2=True, impersonate="chrome", aria2_conns=16
                    )
                    ret_fb, stderr_fb = run_process_with_heartbeat(
                        cmd_fallback, job_id, "Downloading via page extractor...",
                        timeout_sec=900.0, watch_dir=job_dir
                    )
                    if ret_fb == 0 and len(valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)) > 0:
                        success = True
                    else:
                        stderr_text += f"\n{stderr_fb}"

            # Playwright fallback if still not succeeded
            if not success:
                _clear_job_dir(job_dir)
                log_state(job_id, "resolving_stream")
                call_api(f"/internal/update/{job_id}", {
                    "phase_detail": "Resolving stream via headless browser..."
                })
                if is_crawled_item:
                    candidates = [raw_url]
                    pw_nav_target = raw_url
                else:
                    candidates = [u for u in [page_url, referer, raw_url] if u]
                    pw_nav_target = page_url or raw_url

                pw_stream = resolve_with_playwright(candidates, pw_nav_target, cookies or "", user_agent or "")
                if pw_stream and pw_stream.get("url"):
                    stream_url = pw_stream["url"]
                    pw_ref = pw_stream.get("referer") or referer
                    pw_cook = pw_stream.get("cookies") or cookies
                    pw_ua = pw_stream.get("user_agent") or user_agent
                    cmd_pw = build_ytdlp_cmd(
                        stream_url, job_dir, out_tmpl, target_height, pw_ua, pw_ref, pw_cook,
                        use_aria2=True, aria2_conns=16
                    )
                    ret_pw, stderr_pw = run_process_with_heartbeat(
                        cmd_pw, job_id, "Downloading resolved stream...",
                        timeout_sec=900.0, watch_dir=job_dir
                    )
                    if ret_pw == 0 and len(valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)) > 0:
                        success = True
                    else:
                        stderr_text += f"\n{stderr_pw}"

        downloaded_files = valid_upload_candidates(job_dir, plugin, expected_is_direct_doc)
        if not success or not downloaded_files:
            all_files = [f for f in pathlib.Path(job_dir).rglob("*") if f.is_file()]
            rejection_reasons = []
            for f in all_files:
                ok, reason = is_valid_upload_candidate(f, plugin, expected_is_direct_doc)
                if not ok:
                    rejection_reasons.append(f"{f.name}: {reason}")
            if rejection_reasons:
                raise RuntimeError(f"Rejected invalid download candidates: {'; '.join(rejection_reasons[:3])}")
            err_msg = stderr_text[-400:] if stderr_text else "Download failed"
            raise RuntimeError(sanitize_text(err_msg))

        target_file = max(downloaded_files, key=lambda f: f.stat().st_size)
        file_path = str(target_file)
        final_fn = target_file.name

        # Auto-extract archives if enabled
        is_archive = target_file.suffix.lower() in (".zip", ".rar", ".7z", ".001") or ".part1.rar" in final_fn.lower()
        if auto_extract and is_archive:
            log_state(job_id, "extracting")
            call_api(f"/internal/update/{job_id}", {
                "phase_detail": "Extracting archive in cloud..."
            })
            extracted_dir = os.path.join(job_dir, "extracted")
            extracted_files = extract_archive_zipslip_safe(file_path, extracted_dir, skip_junk=True)

            if extracted_files:
                for ext_f in extracted_files:
                    ef_path = ext_f
                    ef_name = os.path.basename(ext_f)
                    if ef_path.lower().endswith((".mp4", ".mkv", ".webm", ".mov", ".m4v", ".ts")):
                        ef_path = rebuild_video(ef_path)
                    fsize = os.path.getsize(ef_path)
                    call_api(f"/internal/update/{job_id}", {
                        "status": "uploading_to_gdrive",
                        "filename": ef_name,
                        "total_bytes": fsize,
                        "phase_detail": f"Uploading extracted file ({format_size(fsize)})..."
                    })
                    uploader.upload_file(ef_path, ef_name, folder_id, job_id)

                log_state(job_id, "completed")
                call_api(f"/internal/update/{job_id}", {
                    "status": "completed",
                    "progress": 100.0,
                    "speed_text": "",
                    "phase_detail": f"Extracted and saved {len(extracted_files)} files to Drive"
                })
                return

        # Rebuild & Verify Video
        if target_file.suffix.lower() in (".mp4", ".mkv", ".webm", ".mov", ".m4v", ".ts"):
            log_state(job_id, "rebuilding")
            call_api(f"/internal/update/{job_id}", {
                "phase_detail": "Rebuilding seekable MP4..."
            })
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
            "progress": 0.0,
            "downloaded_bytes": 0,
            "total_bytes": fsize,
            "speed_text": "",
            "phase_detail": "Uploading"
        })

        def on_upload_prog(pct, uploaded_b, tot_b, speed_text=""):
            payload: Dict[str, Any] = {
                "progress": pct,
                "downloaded_bytes": uploaded_b,
                "total_bytes": tot_b,
                "phase_detail": "Uploading to Drive"
            }
            if speed_text:
                payload["speed_text"] = speed_text
            call_api(f"/internal/update/{job_id}", payload)

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
            "speed_text": "",
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
            "error": clean_err,
            "speed_text": ""
        })
        raise
    finally:
        shutil.rmtree(job_dir, ignore_errors=True)
        shutil.rmtree(cdl_appdata_dir, ignore_errors=True)


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

                curl_cmd = ["curl", "-sSL", "--connect-timeout", "15", "--max-time", "1200", "-o", dest_path, item_url]
                if item.get("extra_cookie"):
                    curl_cmd.extend(["-H", f"Cookie: {item['extra_cookie']}"])

                ret, _ = run_process_with_heartbeat(curl_cmd, job_id, f"Downloading item {idx+1}/{total}...", timeout_sec=1200)

                if ret == 0 and os.path.exists(dest_path) and os.path.getsize(dest_path) > 1024:
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


def dispatch_job(job: Dict[str, Any], uploader: GoogleDriveUploader) -> None:
    mode = job.get("job_mode", "single")
    if mode == "linkgrabber_analyze":
        execute_linkgrabber_analyze(job)
    elif mode == "batch_direct":
        execute_batch_direct(job, uploader)
    else:
        execute_single_download(job, uploader)


def main():
    if not JOB_ID or not WORKER_URL or not API_SECRET:
        sys.stderr.write("Missing mandatory environment variables\n")
        sys.exit(1)

    uploader = GoogleDriveUploader(GDRIVE_CLIENT_ID, GDRIVE_CLIENT_SECRET, GDRIVE_REFRESH_TOKEN)
    log_state(JOB_ID, "booting")

    try:
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

        try:
            dispatch_job(job, uploader)
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

            try:
                next_job = call_api("/internal/claim_next")
            except ControlAbort:
                break
            except Exception:
                break

            if next_job and next_job.get("job_id"):
                next_id = next_job["job_id"]
                log_state(next_id, "warm_claimed")
                try:
                    dispatch_job(next_job, uploader)
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
