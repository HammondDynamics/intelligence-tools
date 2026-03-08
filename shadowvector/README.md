# ShadowVector

**Automated Penetration Testing Orchestration Platform**

ShadowVector is an asynchronous security automation framework designed to orchestrate the initial phases of a penetration test (reconnaissance, enumeration, and vulnerability scanning). 

Instead of executing linear scripts, ShadowVector utilizes an **Intelligent Decision Engine** that parses tool outputs in real-time to dynamically determine the next optimal attack vector.

## ⚙️ Core Architecture

To prevent HTTP blocking during long-running network scans, the system is built on a decoupled Producer/Consumer architecture:

*   **Frontend / API:** Flask (Python)
*   **Message Broker:** Redis
*   **Task Queue / Worker:** Celery
*   **Persistence Layer:** SQLite / SQLAlchemy

### Architecture Flow
1. User submits a target IP and selects an Attack Policy (Fast, Normal, Comprehensive).
2. Flask serializes the request and pushes the task to the Redis message broker, instantly returning a `202 Accepted` state to the UI.
3. A background Celery worker pops the task and initiates the scan sequence via `subprocess`.
4. The frontend asynchronously polls the `/status` endpoint to update the UI without freezing.

## 🧠 The Decision Engine

ShadowVector does not blindly run tools. It analyzes output to build context.

1.  **Reconnaissance:** Executes `nmap` (-sV) and outputs structured XML to a temporary file.
2.  **Data Parsing & Threat Intel:** Python's `xml.etree` parses the open ports and service versions. The engine then cross-references these specific service versions (e.g., `vsftpd 2.3.4`) against a localized **NVD (National Vulnerability Database) JSON feed**.
3.  **Severity Scoring:** Discovered CVEs are automatically scored and flagged (CRITICAL, HIGH, MEDIUM, LOW) based on their CVSS v2/v3 base scores.
4.  **Dynamic Chaining:** Heuristic rules evaluate the parsed data.
    *   *Example:* If `service == 'http'` or `port in [80, 443, 3000]`, the engine dynamically spawns sub-processes for **Nikto** (web vulnerability scanning) and **GoBuster** (directory enumeration).
    *   *Example:* If specific parameters or login pages are discovered, the engine primes **SQLMap** for automated injection testing.

## 🛠️ Integrated Toolchain
*   **Nmap** (Network discovery & version detection)
*   **Nikto** (Web server configuration auditing)
*   **GoBuster** (URI/Directory brute-forcing)
*   **SQLMap** (Automated SQL injection detection)

## ⚠️ Disclaimer
This tool was developed strictly for authorized testing and educational purposes within isolated, virtualized laboratory environments. The operator assumes all liability for the execution of this framework.
