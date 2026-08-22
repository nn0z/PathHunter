# Path Hunter
import os
import requests
import sys
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_banner():
    banner = r"""
    ██████╗  █████╗ ████████╗██╗  ██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔══██╗██╔══██╗╚══██╔══╝██║  ██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██████╔╝███████║   ██║   ███████║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔═══╝ ██╔══██║   ██║   ██╔══██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║     ██║  ██║   ██║   ██║  ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                    [ Sensitive Files & Endpoints High-Speed Scanner ]
    """
    print("\033[1;36m" + banner + "\033[0m")
    print("\033[1;30m" + "=" * 70 + "\033[0m")


def load_paths(filename="endpoints.txt"):
    paths = []
    if os.path.exists(filename):
        with open(filename, "r", encoding="utf-8") as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        print(f"\033[1;32m[+]\033[0m Loaded total \033[1;33m{len(paths)}\033[0m paths from {filename}.")
    else:
        print(f"\033[1;31m[-]\033[0m {filename} not found! Please create the file.")
    return paths


def test_single_path(base_origin, path):
    cleaned_path = path.lstrip('/')
    full_url = urljoin(base_origin, cleaned_path)
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
    try:
        response = requests.head(full_url, headers=headers, timeout=3, allow_redirects=True)
        status_code = response.status_code

        if status_code in [403, 405]:
            response = requests.get(full_url, headers=headers, timeout=3, stream=True)
            status_code = response.status_code

        return (full_url, path, status_code)
    except Exception:
        return (full_url, path, "ERR")


def run_scanner(target_url, sensitive_paths):
    if not target_url.endswith("/"):
        target_url += "/"
        print(f"\033[1;33m[!]\033[0m Target URL normalized (added trailing /): \033[1;35m{target_url}\033[0m")

    parsed_base = urlparse(target_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}{parsed_base.path}"

    total_tests = len(sensitive_paths)
    valid_results = []
    completed_count = 0

    status_counts = {
        200: 0,
        302: 0,
        400: 0,
        403: 0,
        405: 0,
        404: 0,
        500: 0,
        503: 0,
        "Other": 0
    }

    print(f"\n\033[1;33m[*]\033[0m Starting live scan... Target: \033[1;35m{base_origin}\033[0m | Total paths: \033[1;35m{total_tests}\033[0m\n" + "\033[1;30m" + "=" * 70 + "\033[0m")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_single_path, base_origin, path): path for path in sensitive_paths}

        for future in as_completed(futures):
            completed_count += 1
            full_url, path, status_code = future.result()

            if status_code in status_counts:
                status_counts[status_code] += 1
            else:
                status_counts["Other"] += 1

            if status_code != 404 and status_code != "ERR":
                valid_results.append((status_code, full_url, path))
                if status_code == 200:
                    status_str = f"\033[92m[{status_code}]\033[0m"
                elif status_code == 302:
                    status_str = f"\033[90m[{status_code}]\033[0m"
                elif status_code in [400, 403, 405]:
                    status_str = f"\033[93m[{status_code}]\033[0m"
                else:
                    status_str = f"\033[94m[{status_code}]\033[0m"

                sys.stdout.write(f"\r\033[K\033[1;31m[+] FOUND:\033[0m {status_str} \033[1;32m{path}\033[0m -> {full_url}\n")
                sys.stdout.flush()

            if completed_count % 20 == 0 or completed_count == total_tests:
                status_line = (
                    f"\r\033[K\033[1;36m[*] Scanning [{completed_count} / {total_tests}]\033[0m | "
                    f"\033[32m200: {status_counts[200]}\033[0m | "
                    f"\033[30m302: {status_counts[302]}\033[0m | "
                    f"\033[33m403: {status_counts[403]}\033[0m | "
                    f"\033[31m404: {status_counts[404]}\033[0m | "
                    f"\033[34m500: {status_counts[500]}\033[0m"
                )
                sys.stdout.write(status_line)
                sys.stdout.flush()

    print("\n\n\033[1;30m" + "=" * 70 + "\033[0m")
    print(f"\033[1;32m[*]\033[0m Scan finished. Found \033[1;33m{len(valid_results)}\033[0m active endpoints/files.")

    if valid_results:
        print(f"\n\033[1;31m[+] Summary: Discovered active/other endpoints:\033[0m\n")
        for idx, (status, full_url, path) in enumerate(valid_results, 1):
            if status == 200:
                colored_status = f"\033[92m[{status}]\033[0m"
            elif status == 302:
                colored_status = f"\033[90m[{status}]\033[0m"
            elif status in [400, 403, 405]:
                colored_status = f"\033[93m[{status}]\033[0m"
            else:
                colored_status = f"\033[94m[{status}]\033[0m"
            print(f" \033[1;33m{idx}.\033[0m {colored_status} {path} -> \033[1;32m{full_url}\033[0m")

        print("\n\033[1;30m" + "-" * 70 + "\033[0m")
        save_choice = input("\033[1;36m[?] Do you want to save results to a .txt file? (y/n): \033[0m").strip().lower()
        if save_choice == 'y':
            filename = input("\033[1;36m[?] Enter filename: \033[0m").strip()
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

                print(f"\033[1;32m[+]\033[0m Results successfully saved to \033[1;33m{filename}\033[0m")
    else:
        print("\033[1;33m[-]\033[0m No active endpoints found.")


if __name__ == "__main__":
    clear_screen()
    print_banner()

    sensitive_paths = load_paths()
    if not sensitive_paths:
        sys.exit()

    target_input = input("\n\033[1;36m[?] Enter target URL: \033[0m").strip()
    if not target_input:
        print("\033[1;31m[-]\033[0m URL cannot be empty.")
        sys.exit()

    run_scanner(target_input, sensitive_paths)
