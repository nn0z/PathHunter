# Path Hunter 

**Path Hunter** is a specialized, high-performance security utility written in Python, meticulously tailored for penetration testing, web assessments, and bug bounty hunting workflows. It automates the discovery of exposed configuration files, administrative panels, sensitive endpoints, and forgotten backup archives across target web assets.

---

## 🚀 Key Features

* **Multi-Threaded Concurrency:** Leverages `ThreadPoolExecutor` for fast parallel execution while maintaining safe rate-limiting intervals to avoid triggering defensive rate-limiters.
* **Smart HTTP Fallback:** Automatically switches from fast `HEAD` probes to verification `GET` requests when encountering `403 Forbidden` or `405 Method Not Allowed` status codes.
* **Source Code Obfuscation:** Keeps sensitive target paths encoded in Base64 arrays to secure the script template and prevent easy static signature detection.
* **Target Filtering & Preview:** Instantly filters out irrelevant `404 Not Found` responses, outputting a clean, color-coded preview of live assets before prompting to save.
* **Persistent Multi-Session Logging:** Appends newly discovered endpoints to existing result files with clean multi-line spacing, preserving historical scan data across multiple bounty targets.

---

## 🛠️ Requirements & Installation

Make sure you have Python 3 installed along with the required `requests` library.

---

## Disclaimer
Path Hunter is developed for authorized penetration testing, security auditing, and bug bounty hunting only.
The authors assume no liability and are not responsible for any misuse or damage caused by this program.
Always ensure you have explicit written permission from the target system owner before scanning.
