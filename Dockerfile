# Python-Image laden
FROM python:3.9

# Arbeitsverzeichnis setzen
WORKDIR /app

# Abhängigkeiten kopieren und installieren
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Quellcode kopieren
COPY . .

# Port setzen (Cloud Run nutzt dynamische Ports)
ENV PORT=8080

# Flask-App starten
CMD exec gunicorn --bind :$PORT main:app
