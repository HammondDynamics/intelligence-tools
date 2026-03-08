import subprocess
import xml.etree.ElementTree as ET
import json
import os
import tempfile
from flask import Flask, render_template, request, Response, jsonify
from celery import Celery
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config["CELERY_BROKER_URL"] = "redis://localhost:6379/0"
app.config["CELERY_RESULT_BACKEND"] = "redis://localhost:6379/0"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///scans.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(100), nullable=False)
    scan_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    policy = db.Column(db.String(50))
    ports_found = db.Column(db.Integer)
    critical_vulns = db.Column(db.Integer)
    scan_data = db.Column(db.Text)


celery = Celery(app.name, broker=app.config["CELERY_BROKER_URL"])
celery.conf.update(app.config)


def find_cves_for_service(product, version):
    cve_file_path = os.path.join("cve_data", "nvdcve-1.1-2011.json")
    found_cves = []
    if not os.path.exists(cve_file_path):
        return []
    with open(cve_file_path, "r", encoding="utf-8") as f:
        cve_data = json.load(f)
    for item in cve_data.get("CVE_Items", []):
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        cvss_score = 0.0
        severity = "UNKNOWN"
        impact = item.get("impact", {})
        if "baseMetricV2" in impact:
            cvss_score = impact["baseMetricV2"].get("cvssV2", {}).get("baseScore", 0.0)
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"
        for node in item.get("configurations", {}).get("nodes", []):
            for cpe_match in node.get("cpe_match", []):
                uri = cpe_match.get("cpe23Uri", "")
                if product.lower() in uri and version in uri:
                    cve_info = {"id": cve_id, "score": cvss_score, "severity": severity}
                    if cve_info not in found_cves:
                        found_cves.append(cve_info)
    return found_cves


@celery.task(soft_time_limit=300)
def run_scan_task(target_ip, scan_policy="normal"):
    temp_xml_file = tempfile.NamedTemporaryFile(mode="w+", suffix=".xml", delete=False)
    temp_xml_path = temp_xml_file.name
    temp_xml_file.close()

    if scan_policy == "fast":
        nmap_command = ["nmap", "-Pn", "-T4", "-F", target_ip, "-oX", temp_xml_path]
    elif scan_policy == "comprehensive":
        nmap_command = [
            "nmap",
            "-Pn",
            "-sV",
            "-sC",
            "-A",
            "-T4",
            target_ip,
            "-oX",
            temp_xml_path,
        ]
    else:
        nmap_command = ["nmap", "-Pn", "-sV", "-T4", target_ip, "-oX", temp_xml_path]

    try:
        nmap_result = subprocess.run(
            nmap_command, capture_output=True, text=True, timeout=120
        )
        if nmap_result.returncode != 0:
            os.unlink(temp_xml_path)
            return {"error": f"Nmap failed: {nmap_result.stderr}"}

        with open(temp_xml_path, "r") as f:
            xml_content = f.read()
        os.unlink(temp_xml_path)

        open_ports = []
        root = ET.fromstring(xml_content)
        for port in root.findall(".//port"):
            state_elem = port.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue
            service = port.find("service")
            if service is None:
                continue
            product = service.get("product", "")
            version = service.get("version", "")
            cves = (
                find_cves_for_service(product, version) if product and version else []
            )
            has_critical = (
                any(c.get("severity") == "CRITICAL" for c in cves) if cves else False
            )
            has_high = any(c.get("severity") == "HIGH" for c in cves) if cves else False
            port_info = {
                "port_id": port.get("portid"),
                "service_name": service.get("name", "unknown"),
                "version": f"{product} {version}".strip() or "unknown",
                "cves": cves,
                "has_critical": has_critical,
                "has_high": has_high,
            }
            open_ports.append(port_info)

        nikto_output = None
        gobuster_output = None
        sqlmap_output = None

        for port_info in open_ports:
            if "http" in port_info["service_name"] or port_info["port_id"] in [
                "80",
                "443",
                "3000",
                "8000",
                "8080",
                "8180",
            ]:
                print(f"Web server found. Running Nikto and GoBuster...")
                nikto_command = [
                    "nikto",
                    "-h",
                    target_ip,
                    "-p",
                    port_info["port_id"],
                    "-maxtime",
                    "60s",
                ]
                nikto_result = subprocess.run(
                    nikto_command, capture_output=True, text=True, timeout=120
                )
                nikto_output = nikto_result.stdout

                gobuster_command = [
                    "gobuster",
                    "dir",
                    "-u",
                    f"http://{target_ip}",
                    "-w",
                    "/usr/share/dirb/wordlists/small.txt",
                    "-q",
                    "--timeout",
                    "10s",
                ]
                gobuster_result = subprocess.run(
                    gobuster_command, capture_output=True, text=True, timeout=120
                )
                gobuster_output = (
                    gobuster_result.stdout if gobuster_result.stdout.strip() else None
                )

                print(f"Testing for SQL Injection vulnerabilities...")
                test_urls = [
                    f"http://{target_ip}/index.php?id=1",
                    f"http://{target_ip}/login.php?user=test",
                    f"http://{target_ip}/search.php?q=test",
                ]
                for test_url in test_urls:
                    sqlmap_command = [
                        "sqlmap",
                        "-u",
                        test_url,
                        "--batch",
                        "--level=1",
                        "--risk=1",
                        "--answers=follow=N",
                        "--timeout=30",
                    ]
                    sqlmap_result = subprocess.run(
                        sqlmap_command, capture_output=True, text=True, timeout=90
                    )
                    if "vulnerable" in sqlmap_result.stdout.lower():
                        sqlmap_output = sqlmap_result.stdout
                        print(f"SQLMap found vulnerability on {test_url}!")
                        break
                break

        return {
            "ports": open_ports,
            "nikto_output": nikto_output,
            "gobuster_output": gobuster_output,
            "sqlmap_output": sqlmap_output,
            "target": target_ip,
        }
    except Exception as e:
        if os.path.exists(temp_xml_path):
            os.unlink(temp_xml_path)
        return {"error": str(e)}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    target_ip = request.form.get("target_ip")
    scan_policy = request.form.get("scan_policy", "normal")
    if not target_ip:
        return "Please provide a target IP.", 400

    task = run_scan_task.delay(target_ip, scan_policy)

    new_scan = ScanResult(
        target=target_ip,
        policy=scan_policy,
        ports_found=0,
        critical_vulns=0,
        scan_data=task.id,
    )
    db.session.add(new_scan)
    db.session.commit()

    return render_template("results.html", task_id=task.id, target=target_ip)


@app.route("/status/<task_id>")
def taskstatus(task_id):
    task = run_scan_task.AsyncResult(task_id)
    if task.state == "PENDING":
        response = {"state": task.state, "status": "Pending..."}
    elif task.state == "SUCCESS":
        response = {"state": task.state, "status": "Complete!", "result": task.result}
    elif task.state == "FAILURE":
        response = {"state": task.state, "status": "Failed", "error": str(task.info)}
    else:
        response = {"state": task.state, "status": "Running..."}

    if task.state == "SUCCESS" and task.result:
        scan_record = ScanResult.query.filter_by(scan_data=task_id).first()
        if scan_record and scan_record.ports_found == 0:
            result = task.result
            scan_record.ports_found = len(result.get("ports", []))
            scan_record.critical_vulns = sum(
                1 for p in result.get("ports", []) if p.get("has_critical")
            )
            scan_record.scan_data = json.dumps(result)
            db.session.commit()

    return jsonify(response)


@app.route("/download-report/<task_id>")
def download_report(task_id):
    task = run_scan_task.AsyncResult(task_id)
    if task.state != "SUCCESS":
        return "Report not ready.", 400
    result = task.result
    target = result["target"]
    ports = result["ports"]
    nikto = result.get("nikto_output", "")
    gobuster = result.get("gobuster_output", "")
    sqlmap = result.get("sqlmap_output", "")
    lines = []
    lines.append("=" * 70)
    lines.append("SHADOWVECTOR SECURITY SCAN REPORT")
    lines.append("=" * 70)
    lines.append(f"Target: {target}")
    lines.append("")
    lines.append("--- OPEN PORTS AND SERVICES ---")
    for port in ports:
        lines.append(
            f"Port {port['port_id']}: {port['service_name']} - {port['version']}"
        )
        if port.get("cves"):
            for cve in port["cves"]:
                if isinstance(cve, dict) and cve.get("id"):
                    lines.append(
                        f"  >> {cve['id']} - {cve['severity']} (Score: {cve['score']})"
                    )
    lines.append("")
    if nikto:
        lines.append("--- NIKTO WEB SCAN ---")
        lines.append(nikto)
    if gobuster:
        lines.append("--- GOBUSTER DIRECTORY SCAN ---")
        lines.append(gobuster)
    if sqlmap:
        lines.append("--- SQLMAP INJECTION TEST ---")
        lines.append(sqlmap)
    lines.append("=" * 70)
    report_content = "\n".join(lines)
    return Response(
        report_content,
        mimetype="text/plain",
        headers={
            "Content-disposition": f"attachment; filename=shadowvector_{target}.txt"
        },
    )


@app.route("/history")
def history():
    all_scans = ScanResult.query.order_by(ScanResult.scan_date.desc()).all()
    return render_template("history.html", scans=all_scans)


@app.route("/view-scan/<int:scan_id>")
def view_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    scan_data = json.loads(scan.scan_data)
    return render_template("view_scan.html", scan=scan, data=scan_data)
