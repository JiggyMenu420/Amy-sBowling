from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
from openpyxl import Workbook
from io import BytesIO
import json
from datetime import datetime

# Flask App Setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session läuft 7 Tage

USER_FILE = 'users.json'
LOG_FILE = 'logs.json'

# ✅ Helper function to load users
def load_users():
    try:
        with open(USER_FILE, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

# ✅ Helper function to save users
def save_users(users):
    with open(USER_FILE, 'w', encoding='utf-8') as file:
        json.dump(users, file, indent=4)

# ✅ Helper function to load logs
def load_logs():
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

# ✅ Helper function to save logs
def save_logs(logs):
    with open(LOG_FILE, 'w', encoding='utf-8') as file:
        json.dump(logs, file, indent=4)

# ✅ Helper function to log actions
def log_action(action, ip_address):
    logs = load_logs()
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "ip_address": ip_address
    }
    logs.append(log_entry)
    save_logs(logs)

# ✅ Helper function to check if user is admin
def is_admin():
    return 'role' in session and session['role'] == 'admin'

# ✅ Login-Route
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()

        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            session['role'] = users[username].get('role', 'user')
            flash('Login erfolgreich', 'success')
            log_action(f"Erfolgreiche Anmeldung von {username}", request.remote_addr)
            return redirect(url_for('dashboard'))
        else:
            log_action(f"Fehlerhafte Anmeldung - Ungültiger Benutzername oder Passwort für {username}", request.remote_addr)
            error = 'Ungültiger Benutzername oder Passwort'

    return render_template('login.html', error=error)

# ✅ Signup-Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    VALID_REGISTRATION_CODE = 'fnuNuhuAF73qr'

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        code = request.form['code']  # Eingabefeld für den Code
        ip_address = request.remote_addr  # IP-Adresse des Benutzers

        # Log registration attempt
        if code != VALID_REGISTRATION_CODE:
            log_action(f"Fehlerhafte Registrierung - Ungültiger Code für {username}", ip_address)
            flash('Ungültiger Registrierungscode', 'error')
            return redirect(url_for('signup'))

        if password == confirm_password:
            hashed_password = generate_password_hash(password)
            users = load_users()

            if username in users:
                log_action(f"Fehlerhafte Registrierung - Benutzername {username} existiert bereits", ip_address)
                flash('Benutzername existiert bereits', 'error')
                return redirect(url_for('signup'))

            users[username] = {'password': hashed_password, 'role': 'user'}
            save_users(users)

            log_action(f"Erfolgreiche Registrierung von {username}", ip_address)
            flash(f'Erfolgreich registriert als {username}', 'success')
            return redirect(url_for('login'))
        else:
            log_action(f"Fehlerhafte Registrierung - Passwörter stimmen nicht überein für {username}", ip_address)
            flash('Passwörter stimmen nicht überein', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')


# ✅ Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    flash('Du musst dich zuerst einloggen', 'error')
    return redirect(url_for('login'))

# ✅ Admin-Panel und Logs-Seite
@app.route('/admin_panel')
def admin_panel():
    if is_admin():
        users = load_users()
        return render_template('admin_panel.html', users=users)
    flash('Zugriff verweigert: Nur für Admins', 'error')
    return redirect(url_for('login'))

# ✅ Logs-Route
@app.route('/logs')
def logs():
    if is_admin():
        logs = load_logs()
        return render_template('logs.html', logs=logs)
    flash('Zugriff verweigert: Nur für Admins', 'error')
    return redirect(url_for('login'))

# ✅ Logout
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Du wurdest erfolgreich ausgeloggt', 'info')
    return redirect(url_for('login'))

# ✅ Rechner
@app.route('/rechner')
def rechner():
    if 'username' in session:  # Prüfen, ob der Benutzer eingeloggt ist
        return render_template('rechner.html')  # Lade die Rechner-Seite
    flash('Du musst dich einloggen, um auf diese Seite zuzugreifen', 'error')  # Fehlermeldung
    return redirect(url_for('login'))  # Weiterleitung zur Login-Seite


# ✅ Rechnungen-Seite
@app.route('/rechnungen')
def rechnungen():
    if 'username' in session:
        return render_template('rechnungen.html')
    flash('Du musst dich einloggen, um auf diese Seite zuzugreifen', 'error')
    return redirect(url_for('login'))

# ✅ Team-Seite
@app.route('/team')
def team():
    if 'username' in session:
        return render_template('team.html')
    flash('Du musst dich einloggen, um auf diese Seite zuzugreifen', 'error')
    return redirect(url_for('login'))


# ✅ Download Rechnungen als Excel
@app.route('/download_rechnungen')
def download_rechnungen():
    rechnungen = [
        {"datum": "2025-03-10", "mitarbeiter": "John Doe", "produkte": "Bowling, Getränke", "total": 35.50},
        {"datum": "2025-03-11", "mitarbeiter": "Jane Smith", "produkte": "Bowling, Snacks", "total": 25.00},
    ]

    wb = Workbook()
    ws = wb.active
    ws.title = "Rechnungen"
    ws.append(["Datum", "Mitarbeiter", "Produkte", "Total (€)"])

    for rechnung in rechnungen:
        ws.append([rechnung['datum'], rechnung['mitarbeiter'], rechnung['produkte'], rechnung['total']])

    file_stream = BytesIO()
    wb.save(file_stream)
    file_stream.seek(0)

    return send_file(file_stream, as_attachment=True, download_name="rechnungen.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)