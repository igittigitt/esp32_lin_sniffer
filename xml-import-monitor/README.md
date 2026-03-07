# AlfaXML Import Monitor

Docker-basiertes Monitoring für AlfaMediaPlan XML-Importe.

## Features

- **Live-Status**: Zeigt aktuell verarbeitete XML-Pläne in Echtzeit (WebSocket)
- **Tagesstatistik**: Balkendiagramm 00:00–23:55 im 5-Minuten-Raster
- **Ereignistabelle**: Letzte 50 Import-Ereignisse mit Status
- **KPI-Karten**: Aktiv / Erfolgreich / Abgelehnt / Fehlgeschlagen

## Voraussetzungen

- Docker + Docker Compose auf dem Server
- Lesezugriff auf `/home/ngio/LogFile` und die Basket-Verzeichnisse

## Schnellstart

```bash
cd xml-import-monitor
docker compose up -d --build
```

Das Web-Frontend ist danach erreichbar unter:
**http://<server-ip>:8080**

## Konfiguration

Die Pfade können in `docker-compose.yml` unter `volumes` und `environment`
angepasst werden:

| Variable  | Standard (im Container) | Gemounteter Host-Pfad |
|-----------|-------------------------|-----------------------|
| `LOG_FILE`| `/logs/LogFile`         | `/home/ngio/LogFile`  |
| `SAFEDIR` | `/watch/SafeDir`        | `/home/ngio/Baskets/In/AlfaXmlImport/SafeDir` |
| `REJECTED`| `/watch/Rejected`       | `/home/ngio/Baskets/In/AlfaXmlImport/Rejected` |
| `DB_PATH` | `/data/monitor.db`      | Docker Volume `alfa-monitor-data` |

## Port ändern

In `docker-compose.yml` unter `ports`:
```yaml
ports:
  - "9090:8080"   # Host-Port:Container-Port
```

## Logs

```bash
docker compose logs -f
```

## Datenbankinhalt prüfen

```bash
docker exec alfa-xml-monitor python -c "
import sqlite3, json
con = sqlite3.connect('/data/monitor.db')
rows = con.execute('SELECT log_date, status, COUNT(*) FROM imports GROUP BY log_date, status').fetchall()
for r in rows: print(r)
"
```

## Funktionsweise

1. **LogWatcher** (Thread): Tailed `/home/ngio/LogFile` und erkennt:
   - `Called with` → Import gestartet
   - `Managed to handle` → Import erfolgreich
   - `Done` → Import abgeschlossen
2. **DirWatcher** (Thread): Pollt `SafeDir` und `Rejected` alle 10 s als Fallback
3. **SQLite** speichert alle Ereignisse mit 5-Minuten-Slot für die Statistik
4. **WebSocket** pusht Updates alle 2 Sekunden an alle Browser-Clients
