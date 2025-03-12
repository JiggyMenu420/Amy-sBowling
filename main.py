from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
from openpyxl import Workbook
from io import BytesIO
import json
from datetime import datetime
import os

# Flask App Setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Session läuft 7 Tage

USER_FILE = 'users.json'
LOG_FILE = 'logs.json'
KONTAKTE_FILE = 'kontakte.json'

# Helper function to load users
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, 'r', encoding='utf-8') as file:
            return json.load(file)
    return {}

# Helper function to save users
def save_users(users):
    with open(USER_FILE, 'w', encoding='utf-8') as file:
        json.dump(users, file, indent=4)

# Helper function to load logs
def load_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', encoding='utf-8') as file:
            return json.load(file)
    return []

def lade_kontakte():
    try:
        with open(KONTAKTE_FILE, 'r', encoding='utf-8') as file:
            kontakte = json.load(file)
            # Sortiere Kontakte nach Rang, wobei die höheren Ränge zuerst kommen
            kontakte.sort(key=lambda x: x['rang'], reverse=True)
            return kontakte
    except FileNotFoundError:
        return []  # Wenn keine Datei existiert, gebe eine leere Liste zurück
    except json.JSONDecodeError:
        return []  # Falls die JSON-Datei leer oder fehlerhaft ist


# Funktion, um die Kontakte in die JSON-Datei zu speichern
def save_kontakte(kontakte):
    with open('kontakte.json', 'w') as file:
        json.dump(kontakte, file, indent=4)

def is_admin():
    # Stelle sicher, dass die Session-Daten korrekt überprüft werden
    return session.get('role') == 'admin'


# Helper function to notify admins about unauthorized access
def notify_admins(unauthorized_user, ip_address):
    admins = [user for user, details in load_users().items() if details['role'] == 'admin']
    for admin in admins:
        # Benachrichtige jeden Admin, z.B. durch Logging
        log_action(f"Nicht-berechtigter Zugriff auf Admin-Panel von {unauthorized_user} (IP: {ip_address})", admin)


# Helper function to save logs
def save_logs(logs):
    with open(LOG_FILE, 'w', encoding='utf-8') as file:
        json.dump(logs, file, indent=4)

# Helper function to log actions
def log_action(action, ip_address):
    logs = load_logs()
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": action,
        "ip_address": ip_address
    }
    logs.append(log_entry)
    save_logs(logs)

def log_failed_access(username, ip_address):
    logs = load_logs()  # Lade die vorhandenen Logs
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "action": f"Zugriffsversuch auf Admin-Panel von nicht berechtigtem Benutzer: {username}",
        "ip_address": ip_address
    }
    logs.append(log_entry)  # Füge das Log hinzu
    save_logs(logs)  # Speichere die Logs

# Helper function to check if user is admin
def is_admin():
    return 'role' in session and session['role'] == 'admin'

@app.after_request
def add_cache_control(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

# Login-Route
@app.route('/', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        # Wenn der Benutzer bereits eingeloggt ist, leite ihn direkt zum Dashboard weiter
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            session['role'] = users[username]['role']  # Die Rolle des Benutzers wird gespeichert

            return redirect(url_for('dashboard'))  # Weiterleitung zum Dashboard nach erfolgreichem Login
        else:
            return redirect(url_for('login'))

    return render_template('login.html')




# Signup-Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    VALID_REGISTRATION_CODE = 'Amy'

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        code = request.form['code']
        ip_address = request.remote_addr

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

# Dashboard-Route
@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    flash('Du musst dich zuerst einloggen', 'error')
    return redirect(url_for('login'))

# Admin-Panel und Logs-Seite
@app.route('/admin_panel')
def admin_panel():
    # Überprüfe, ob der Benutzer in der Session ist und Admin-Rechte hat
    if 'username' in session and is_admin():
        users = load_users()
        logs = load_logs()
        print(f"Admin Panel Zugriff von {session['username']}")  # Debug-Ausgabe
        return render_template('admin_panel.html', users=users, logs=logs)

    # Wenn der Benutzer kein Admin ist, logge den Versuch und benachrichtige die Admins
    ip_address = request.remote_addr
    username = session.get('username', 'Unbekannter Benutzer')
    print(f"Fehlgeschlagener Zugriff durch {username} von {ip_address}")

    log_failed_access(username, ip_address)
    notify_admins(username, ip_address)

    return redirect(url_for('dashboard'))



# In der Funktion, die die Logs lädt
@app.route('/logs')
def logs():
    if is_admin():
        logs = load_logs()
        logs.reverse()  # Kehrt die Reihenfolge der Logs um, sodass die neuesten oben sind
        return render_template('logs.html', logs=logs)
    flash('Zugriff verweigert: Nur für Admins', 'error')
    return redirect(url_for('login'))


# Logout-Route
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

# Rechner-Route
@app.route('/rechner')
def rechner():
    if 'username' in session:
        return render_template('rechner.html')
    flash('Du musst dich einloggen, um auf diese Seite zuzugreifen', 'error')
    return redirect(url_for('login'))

# Rechnungen-Seite
@app.route('/rechnungen')
def rechnungen():
    # Überprüfe den Admin-Status
    is_admin = 'role' in session and session['role'] == 'admin'  # Wenn der Benutzer ein Admin ist
    return render_template('rechnungen.html', is_admin=is_admin)



# Team-Seite
@app.route('/team')
def team():
    if 'username' in session:
        return render_template('team.html')
    flash('Du musst dich einloggen, um auf diese Seite zuzugreifen', 'error')
    return redirect(url_for('login'))

# Passwort für einen anderen Benutzer ändern (Admin-Funktion)
@app.route('/change_password/<username>', methods=['POST'])
def change_password_for_user(username):
    if not is_admin():
        flash('Zugriff verweigert: Nur für Admins', 'error')
        return redirect(url_for('login'))

    # Neues Passwort aus dem Body extrahieren
    data = request.get_json()
    new_password = data.get('new_password')

    if not new_password:
        return jsonify({'success': False, 'message': 'Kein Passwort angegeben.'}), 400

    # Passwort für den angegebenen Benutzer ändern
    users = load_users()
    if username not in users:
        return jsonify({'success': False, 'message': 'Benutzer nicht gefunden.'}), 404

    hashed_password = generate_password_hash(new_password)
    users[username]['password'] = hashed_password
    save_users(users)

    return jsonify({'success': True, 'message': f'Passwort für {username} wurde erfolgreich geändert.'})


# Passwort ändern Route
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Überprüfen, ob die Passwörter übereinstimmen
        if new_password != confirm_password:
            flash('Die Passwörter stimmen nicht überein.', 'error')
            return redirect(url_for('change_password'))

        # Hashen des neuen Passworts
        hashed_password = generate_password_hash(new_password)

        username = session.get('username')
        if username:
            users = load_users()
            if username in users:
                users[username]['password'] = hashed_password
                save_users(users)

                # Benutzer ausloggen
                session.pop('username', None)
                session.pop('role', None)

                # Kein flash gesetzt, direkt zur Login-Seite
                return redirect(url_for('login'))  # Benutzer wird zum Login weitergeleitet

        flash('Fehler beim Ändern des Passworts.', 'error')
        return redirect(url_for('change_password'))

    return render_template('change_password.html')

@app.route('/user_logs/<username>')
def user_logs(username):
    if is_admin():
        # Lade alle Logs
        logs = load_logs()

        # Filtere die Logs für den spezifischen Benutzer
        user_logs = [log for log in logs if f"Zugriffsversuch auf Admin-Panel von nicht berechtigtem Benutzer: {username}" in log['action']]

        return render_template('user_logs.html', username=username, logs=user_logs)
    flash('Zugriff verweigert: Nur für Admins', 'error')
    return redirect(url_for('login'))


# Route zum Löschen eines Benutzers
@app.route('/delete_user/<username>', methods=['POST'])
def delete_user(username):
    if is_admin():
        users = load_users()
        if username in users:
            del users[username]
            save_users(users)
            return redirect(url_for('admin_panel'))
        flash(f"Benutzer {username} nicht gefunden.", 'error')
        return redirect(url_for('admin_panel'))
    flash('Zugriff verweigert: Nur für Admins', 'error')
    return redirect(url_for('login'))

@app.route('/mitarbeiter_kontakte', methods=['GET', 'POST'])
def mitarbeiter_kontakte():
    if request.method == 'POST':
        rang = request.form['rang']
        name = request.form['name']
        nummer = request.form['nummer']
        
        # Neues Kontaktobjekt erstellen
        neuer_kontakt = {
            'rang': int(rang),
            'name': name,
            'nummer': nummer
        }
        
        # Lade aktuelle Kontakte
        kontakte = lade_kontakte()
        kontakte.append(neuer_kontakt)  # Neuen Kontakt hinzufügen
        
        # Kontakte in der JSON-Datei speichern
        save_kontakte(kontakte)
        
        flash('Kontakt wurde erfolgreich hinzugefügt.', 'success')
        return redirect(url_for('mitarbeiter_kontakte'))

    kontakte = lade_kontakte()  # Lade Kontakte und zeige sie im Template
    return render_template('mitarbeiter_kontakte.html', kontakte=kontakte)




@app.route('/loesche_kontakt/<int:index>', methods=['POST'])
def loesche_kontakt(index):
    kontakte = lade_kontakte()

    if 'role' not in session or session['role'] != 'admin':
        flash('Nur Admins können Kontakte löschen.', 'error')
        return redirect(url_for('mitarbeiter_kontakte'))

    if 0 <= index < len(kontakte):
        kontakte.pop(index)  # Löscht den Kontakt mit dem übergebenen Index
        save_kontakte(kontakte)  # Speichert die geänderte Liste
        flash('Kontakt wurde erfolgreich gelöscht.', 'success')
    else:
        flash('Kontakt konnte nicht gefunden werden.', 'error')

    return redirect(url_for('mitarbeiter_kontakte'))




# Download Rechnungen als Excel
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