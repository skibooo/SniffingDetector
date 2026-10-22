from flask import Flask, render_template, redirect, url_for, session, request, jsonify
from database import init_db, get_all_alerts, clear_alerts
from capture import start_capture_thread, stop_capture, is_monitoring, get_interfaces, get_default_interface, get_stats

app = Flask(__name__)
app.secret_key = "sniffing_detector_secret_key"

# Admin credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


@app.route("/")
def index():
    """
    Root route — redirects to dashboard
    if logged in, otherwise to login page.
    """
    if "logged_in" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    Login page — authenticates the administrator.
    """
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password. Please try again."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """
    Logs the administrator out and
    redirects to login page.
    """
    session.clear()
    stop_capture()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    """
    Main dashboard — shows all alerts,
    monitoring status, and system controls.
    """
    if "logged_in" not in session:
        return redirect(url_for("login"))

    alerts = get_all_alerts()
    monitoring = is_monitoring()
    interfaces = get_interfaces()
    default_iface = get_default_interface()

    return render_template(
        "dashboard.html",
        alerts=alerts,
        monitoring=monitoring,
        interfaces=interfaces,
        default_iface=default_iface
    )


@app.route("/start", methods=["POST"])
def start():
    """
    Starts packet capture on the
    selected network interface.
    """
    if "logged_in" not in session:
        return redirect(url_for("login"))

    interface = request.form.get("interface")
    start_capture_thread(interface=interface)
    return redirect(url_for("dashboard"))


@app.route("/stop", methods=["POST"])
def stop():
    """
    Stops packet capture.
    """
    if "logged_in" not in session:
        return redirect(url_for("login"))

    stop_capture()
    return redirect(url_for("dashboard"))


@app.route("/clear", methods=["POST"])
def clear():
    """
    Clears all alerts from the database.
    """
    if "logged_in" not in session:
        return redirect(url_for("login"))

    clear_alerts()
    return redirect(url_for("dashboard"))


@app.route("/api/alerts")
def api_alerts():
    """
    API endpoint that returns alerts as JSON.
    Used for auto-refreshing the dashboard
    without reloading the page.
    """
    if "logged_in" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    alerts = get_all_alerts()
    alert_list = []
    for alert in alerts:
        alert_list.append({
            "id": alert[0],
            "timestamp": alert[1],
            "ip_address": alert[2],
            "mac_address": alert[3],
            "attack_type": alert[4],
            "details": alert[5],
            "recommendation": alert[6]
        })
    return jsonify(alert_list)


@app.route("/api/status")
def api_status():
    """
    Returns current monitoring status as JSON.
    """
    return jsonify({"monitoring": is_monitoring()})


@app.route("/api/stats")
def api_stats():
    """
    Returns live network activity counters as JSON
    (packets captured by protocol, packets per second, uptime).
    """
    if "logged_in" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify(get_stats())


if __name__ == "__main__":
    init_db()
    print("[INFO] Database initialised.")
    print("[INFO] Starting Flask server...")
    print("[INFO] Open your browser and go to http://127.0.0.1:5000")
    app.run(debug=True, use_reloader=False)