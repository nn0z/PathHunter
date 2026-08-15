# Path Hunter v1
import time
import os
import base64
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

ENCODED_PATHS = [
    "L3JvYm90cy50eHQ=", "L3NpdGVtYXAueG1s", "L2Nyb3NzZG9tYWluLnhtbA==", "L2NsaWVudGFjY2Vzc3BvbGljeS54bWw=",
    "Ly53ZWxsLWtub3duL3NlY3VyaXR5LnR4dA==", "Ly53ZWxsLWtub3duL2Fzc2V0bGlua3MuanNvbg==", "Ly53ZWxsLWtub3duL2NoYW5nZS1wYXNzd29yZA==",
    "Ly53ZWxsLWtub3duL21hdHJpeC9zZXJ2ZXI=", "Ly53ZWxsLWtub3duL21hdHJpeC9jbGllbnQ=",
    "Ly5lbnY=", "Ly5lbnYuZXhhbXBsZQ==", "Ly5lbnYubG9jYWw=", "Ly5lbnYucHJvZHVjdGlvbg==", "Ly5lbnYuZGV2ZWxvcG1lbnQ=", "Ly5lbnYuYmFja3Vw",
    "Ly5lbnYuc3RhZ2U=", "Ly5lbnYuc3RhZ2luZw==", "Ly5lbnYudGVzdA==", "Ly5lbnYub2xk", "Ly5lbnYudHh0", "L2Vudi5iYWs=",
    "L2NvbmZpZy5qc29u", "L2NvbmZpZy5waHA=", "L2NvbmZpZy54bWw=", "L2NvbmZpZy55YW1s", "L2NvbmZpZy55bWw=", "L2NvbmZpZy5iYWs=",
    "L3dwLWNvbmZpZy5waHA=", "L2NvbmZpZ3VyYXRpb24ucGhw", "L3NldHRpbmdzLnB5", "L3NldHRpbmdzLmpzb24=", "L3NldHRpbmdzLmxvY2FsLnB5",
    "L3BhcmFtZXRlcnMueW1s", "L2FwcHNldHRpbmdzLmpzb24=", "L2FwcHNldHRpbmdzLkRldmVsb3BtZW50Lmpzb24=", "L2FwcHNldHRpbmdzLlByb2R1Y3Rpb24uanNvbg==",
    "L3dlYi5jb25maWc=", "L2h0dGFjY2Vzcy50eHQ=", "Ly5odHRhY2Nlc3M=", "L25naW54LmNvbmY=", "L2h0dHBkLmNvbmY=", "L2hvc3Rz",
    "L2NvbmZpZ3VyYXRpb24uanNvbg==", "L2NvbmZpZy5pbmMucGhw", "L2xvY2Fsc2V0dGluZ3MucGhw", "L3NldHRpbmdzLnBocA==",
    "Ly5naXQvSEVBRA==", "Ly5naXQvY29uZmln", "Ly5naXQvaW5kZXg=", "Ly5naXRpZ25vcmU=", "Ly5naXQvbG9ncy9IRUFE",
    "Ly5zdm4vZW50cmllcw==", "Ly5zdm4vd2MuZGI=", "Ly5oZy8=", "Ly5ienIv", "L0NWUy9Sb290", "L0NWUy9FbnRyaWVz",
    "L2JhY2t1cC5zcWw=", "L2RhdGFiYXNlLnNxbA==", "L2RiLnNxbA==", "L2R1bXAuc3Fs", "L2JhY2t1cC56aXA=", "L2JhY2t1cC50YXIuZ3o=",
    "L2JhY2t1cC5yYXI=", "L2JhY2t1cC43eg==", "L3NpdGUuYmFr", "L2RiLmJhaw==", "L29sZC8=", "L2FyY2hpdmUv", "L2JhY2t1cC8=", "L2JhY2t1cHMv",
    "L3NxbC5iYWs=", "L2RiX2JhY2t1cC5zcWw=", "L3NpdGVfYmFja3VwLnppcA==", "L2RhdGEuc3Fs", "L2V4cG9ydC5zcWw=", "L2Z1bGxfYmFja3VwLnppcA==",
    "L2JhY2t1cC5zcWwuZ3o=", "L2RiLnppcA==", "L2ZpbGVzLnppcA==", "L2h0bWwuemlw", "L3d3dy56aXA=", "L2JhY2t1cC50YXI=",
    "L3BocGluZm8ucGhw", "L2luZm8ucGhw", "L3Rlc3QucGhw", "L3NlcnZlci1zdGF0dXM=", "L2Vycm9yLmxvZw==", "L2RlYnVnLmxvZw==",
    "L2FjY2Vzcy5sb2c=", "L2Vycm9yX2xvZw==", "L25wbS1kZWJ1Zy5sb2c=", "L2xvZ3Mv", "L2xvZy8=", "L3N0b3JhZ2UvbG9ncy8=",
    "L3N0b3JhZ2UvbG9ncy9sYXJhdmVsLmxvZw==", "L3Zhci9sb2cv", "L3RyYWNlLnR4dA==", "L2RlYnVnLnR4dA==", "L2V4Y2VwdGlvbi5sb2c=",
    "L2Nyb24ubG9n", "L21haWwubG9n", "L2F1dGgubG9n", "L3N5c2xvZw==", "L2FwcGxpY2F0aW9uLmxvZw==",
    "L3BhY2thZ2UuanNvbg==", "L2NvbXBvc2VyLmpzb24=", "L2NvbXBvc2VyLmxvY2s=", "L3BhY2thZ2UtbG9jay5qc29u", "L3lhcm4ubG9jaw==",
    "L0dlbWZpbGU=", "L3JlcXVpcmVtZW50cy50eHQ=", "L3BvbS54bWw=", "L2J1aWxkLmdyYWRsZQ==", "L2NhcmdvLnRvbWw=", "L3BpcGZpbGU=",
    "L3BhY2thZ2VzLmxvY2suanNvbg==", "L2NvbXBvc2VyLnBoYXI=", "L01ha2VmaWxl", "L1Jha2VmaWxl",
    "L0RvY2tlcmZpbGU=", "L2RvY2tlci1jb21wb3NlLnltbA==", "L2RvY2tlci1jb21wb3NlLnlhbWw=", "Ly5kb2NrZXJpZ25vcmU=",
    "L2t1YmVybmV0ZXMueW1s", "L2s4cy55bWw=", "L2hlbG0v", "L2Fuc2libGUv", "L3ZhZ3JhbnRmaWxl",
    "L0plbmtpbnNmaWxl", "Ly50cmF2aXMueW1s", "L2dpdGxhYi1jaS55bWw=", "Ly5naXRodWIvd29ya2Zsb3dzLw==",
    "Ly5jaXJjbGVjaS9jb25maWcueW1s", "L1ZhZ3JhbnRmaWxl", "L3RlcnJhZm9ybS8=", "L2Fuc2libGUuY2Zn",
    "L2FkbWluLw==", "L2FkbWluaXN0cmF0b3Iv", "L2NwYW5lbC8=", "L2Rhc2hib2FyZC8=", "L21hbmFnZS8=", "L21hbmFnZXIv",
    "L2JhY2tlbmQv", "L3Jvb3Qv", "L2FkbWluLnBocA==", "L2FkbWluLmh0bWw=", "L2xvZ2luLw==", "L3NpZ25pbi8=", "L2F1dGgv",
    "L2FkbWluX2FyZWEv", "L2FkbS8=", "L3dlYm1hc3Rlci8=", "L2NvbnRyb2xwYW5lbC8=", "L3N5c2FkbWluLw==", "L3N1cGV1c2VyLw==",
    "L21vZGVyYXRvci8=", "L3N0YWZmLw==", "L3BvcnRhbC8=", "L2NsaWVudHMv", "L3VzZXIvbG9naW4=", "L2FjY291bnRzL2xvZ2luLw==",
    "L2FwaS8=", "L3N3YWdnZXIuanNvbg==", "L3N3YWdnZXIvaW5kZXguaHRtbA==", "L29wZW5hcGkuanNvbg==", "L2dyYXBocWw=", "L2dyYXBoaXFs",
    "L2FwaS92MS8=", "L3YxL2FwaS8=", "L2FwaS92Mi8=", "L3YyLw==", "L3Jlc3Qv", "L3JwYy8=", "L2FwaS9kb2NzLw==",
    "L2FwaS92My8=", "L2FwaS9zd2FnZ2VyLmpzb24=", "L2FwaS1kb2Nz", "L2RvY3Mv", "L3JlZG9j", "L2FwaS9ncmFwaHFs",
    "L2FjdHVhdG9y", "L2FjdHVhdG9yL2Vudg==", "L2FjdHVhdG9yL2hlYWx0aA==", "L2FjdHVhdG9yL21ldHJpY3M=", "L2FjdHVhdG9yL2xvZ2dlcnM=",
    "L2FjdHVhdG9yL21hcHBpbmdz", "L2FjdHVhdG9yL2JlYW5z", "L2FjdHVhdG9yL2NvbmZpZ3Byb3Bz", "L2FjdHVhdG9yL2F1ZGl0ZXZlbnRz",
    "L2FjdHVhdG9yL2h0dHB0cmFjZQ==", "L2FjdHVhdG9yL3RocmVhZGR1bXA=", "L2FjdHVhdG9yL2hlYXBkdW1w",
    "L3RlbGVzY29wZQ==", "L2hvcml6b24v", "L3N0b3JhZ2Uv", "L3ZlbmRvci8=", "L25vZGVfbW9kdWxlcy8=", "L3N0b3JhZ2UvYXBwLw==",
    "L3htbHJwYy5waHA=", "L3dwLWpzb24vd3AvdiYvdXNlcnM=", "L3dwLWpzb24v", "L3dwLWxvZ2luLnBocA==", "L3dwLWNvbnRlbnQv", "L3dwLWluY2x1ZGVzLw==",
    "L3dwLWFkbWluLw==", "L3dwLWNyb24ucGhw", "L3htbHJwYy5waHA/cnNk", "L3dwLWNvbnRlbnQvZGVidWcubG9n", "L3dwLWNvbmZpZy5waHAuYmFr",
    "L2FkbWluaXN0cmF0b3IvaW5kZXgucGhw", "L2pvb21sYS8=", "L2RydXBhbC8=", "L21hZ2VudG8v",
    "L2RlYnVnLw==", "L3Rlc3Qv", "L3Rlc3Rpbmcv", "L3RlbXAv", "L3RtcC8=", "L2Rldi8=", "L3NhbmRib3gv", "L2ludGVybmFsLw==",
    "L3N0YWdpbmcv", "L2JldGEv", "L2RlbW8v", "L29sZF9zaXRlLw==", "L25ldy8=", "L3YxLw==", "L3YyLw==", "L3ByaXZhdGUv",
    "L3NlY3JldC8=", "L2hpZGRlbi8=", "L3NhbXBsZS8=", "L2V4YW1wbGUv",
    "L3BocG15YWRtaW4v", "L3BtYS8=", "L2RiYWRtaW4v", "L215c3FsLw==", "L3NxbG1hbmFnZXIv", "L2FkbWluZXIucGhw", "L3BocG15YWRtaW4vaW5kZXgucGhw",
    "L3BocE15QWRtaW4v", "L1BNQS8=", "L215YWRtaW4v", "L3BocC1teS1hZG1pbi8=", "L3NxbHdlYi8=", "L3NxbGl0ZS8=",
    "L2FkbWluZXIv", "L3BnYWRtaW4v", "L3BocHBnYWRtaW4v", "L3JlZGlzLw==", "L21vbmdvLw=="
]

def get_decoded_paths():
    return [base64.b64decode(p).decode('utf-8') for p in ENCODED_PATHS]

def scan_sensitive_paths(target_url):
    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    sensitive_paths = get_decoded_paths()

    print(f"\n[+] Target Origin: {base_origin}")
    print(f"[+] Scanning {len(sensitive_paths)} common sensitive paths with rate limiting...\n")

    def check_path(path):
        full_url = urljoin(base_origin, path)
        try:
            time.sleep(0.3)
            response = requests.head(full_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                                     timeout=5, allow_redirects=True)
            status_code = response.status_code
            if status_code == 405 or status_code == 403:
                time.sleep(0.3)
                response = requests.get(full_url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'},
                                        timeout=5, stream=True)
                status_code = response.status_code
            return status_code, full_url, path
        except Exception:
            return "ERR", full_url, path

    valid_results = []

    with ThreadPoolExecutor(max_workers=3) as executor:
        results = executor.map(check_path, sensitive_paths)
        for status_code, full_url, path in results:
            if status_code == 200:
                colored_status = f"\033[92m[{status_code}]\033[0m"
            elif status_code == 302:
                colored_status = f"\033[90m[{status_code}]\033[0m"
            elif status_code in [400, 403, 405]:
                colored_status = f"\033[93m[{status_code}]\033[0m"
            elif status_code == 404:
                colored_status = f"\033[91m[{status_code}]\033[0m"
            elif status_code in [500, 503]:
                colored_status = f"\033[94m[{status_code}]\033[0m"
            else:
                colored_status = f"[{status_code}]"

            print(f"{colored_status} {path}")

            if status_code != 404:
                valid_results.append((status_code, full_url, path))

    print("\n========================================")
    print("           Scan Completed              ")
    print("========================================")
    print(f"[+] Found {len(valid_results)} endpoints/files (excluding 404).\n")

    if valid_results:
        print("[+] Discovered active/other endpoints:")
        for status, full_url, path in valid_results:
            if status == 200:
                colored_status = f"\033[92m[{status}]\033[0m"
            elif status == 302:
                colored_status = f"\033[90m[{status}]\033[0m"
            elif status in [400, 403, 405]:
                colored_status = f"\033[93m[{status}]\033[0m"
            elif status in [500, 503]:
                colored_status = f"\033[94m[{status}]\033[0m"
            else:
                colored_status = f"[{status}]"
            print(f" {colored_status} {path} -> {full_url}")
        print("-" * 40)

        save_choice = input("Do you want to save results to a .txt file? (y/n): ").strip().lower()
        if save_choice == 'y':
            filename = input("Enter filename :").strip()
            if filename:
                formatted_lines = [f"[{status}] {path} ({full_url})" for status, full_url, path in valid_results]
                content_to_add = "\n".join(formatted_lines)

                if os.path.exists(filename):
                    with open(filename, "r", encoding="utf-8") as f:
                        existing_content = f.read()

                    with open(filename, "w", encoding="utf-8") as f:
                        if existing_content.strip():
                            f.write(existing_content.rstrip() + "\n\n\n" + content_to_add + "\n")
                        else:
                            f.write(content_to_add + "\n")
                else:
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(content_to_add + "\n")

                print(f"[+] Results successfully saved to {filename}")


if __name__ == "__main__":
    print("========================================")
    print("              Path Hunter v1             ")
    print("    Sensitive Files & Endpoints Scanner ")
    print("========================================")
    target = input("Enter target URL :").strip()
    if target:
        scan_sensitive_paths(target)
    else:
        print("[-] URL cannot be empty.")