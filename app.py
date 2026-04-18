from flask import Flask, render_template, request, send_file, redirect, url_for
import os

# ================================
# IMPORT MODULES
# ================================
from modules.password_logic import analyze_password, generate_password
from modules.packet_logic import analyze_packets
from modules.soc_logic import analyze_logs, generate_soc_report
try:
    from modules.malware_logic import (
        start_monitoring,
        stop_monitoring,
        get_alerts,
        is_monitoring,
        get_global_threat_score
    )
except:
    # fallback for cloud
    def start_monitoring(): pass
    def stop_monitoring(): pass
    def get_alerts(): return []
    def is_monitoring(): return False
    def get_global_threat_score(): return 0

# ================================
# INITIALIZE APP
# ================================
app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)


# ================================
# DASHBOARD
# ================================
@app.route("/")
def dashboard():
    threat_score = get_global_threat_score()

    return render_template(
        "dashboard.html",
        threat_score=threat_score
    )


# ================================
# PASSWORD MODULE
# ================================
from modules.password_logic import (
    analyze_password,
    generate_password,
    enhance_password
)

@app.route("/password", methods=["GET", "POST"])
def password():
    result = None
    generated = None
    enhanced = None

    if request.method == "POST":

        if "password" in request.form:
            pwd = request.form.get("password")
            result = analyze_password(pwd)

        if "generate" in request.form:
            options = {
                "upper": "upper" in request.form,
                "lower": "lower" in request.form,
                "digits": "digits" in request.form,
                "special": "special" in request.form,
                "length": int(request.form.get("length", 12))
            }
            generated = generate_password(options)

        if "enhance" in request.form:
            pwd = request.form.get("enhance_pwd")
            enhanced = enhance_password(pwd)

    return render_template(
        "password.html",
        result=result,
        generated=generated,
        enhanced=enhanced
    )

# ================================
# NETWORK MODULE
# ================================
@app.route("/packet", methods=["GET", "POST"])
def packet():
    analysis = None

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename != "":
            path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(path)
            analysis = analyze_packets(path)

    return render_template("packet.html", analysis=analysis)


# ================================
# SOC MODULE
# ================================
@app.route("/soc", methods=["GET", "POST"])
def soc():
    result = None
    report_path = None

    if request.method == "POST":
        file = request.files.get("file")
        if file:
            path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(path)

            result = analyze_logs(path)
            report_path = generate_soc_report(result)

    return render_template(
        "soc.html",
        result=result,
        report_path=report_path
    )


# ================================
# MALWARE MODULE
# ================================
@app.route("/malware", methods=["GET", "POST"])
def malware():

    if request.method == "POST":
        action = request.form.get("action")

        if action == "start":
            start_monitoring()
        elif action == "stop":
            stop_monitoring()

        return redirect(url_for("malware"))

    return render_template(
        "malware.html",
        alerts=get_alerts(),
        monitoring=is_monitoring(),
        threat_score=get_global_threat_score()
    )


# ================================
# MALWARE APIs
# ================================
@app.route("/malware_alerts")
def malware_alerts():
    return {"alerts": get_alerts()}


@app.route("/malware_threat_score")
def malware_threat_score():
    return {"threat_score": get_global_threat_score()}


# ================================
# DOWNLOAD ROUTE
# ================================
@app.route("/download/<path:path>")
def download(path):
    return send_file(path, as_attachment=True)

@app.route("/docs")
def docs():
    return render_template("docs.html")


# ================================
# RUN APP
# ================================
if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
