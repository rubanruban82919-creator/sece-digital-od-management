# Sri Eshwar Digital OD Management System

## Project structure
- `frontend/` is represented by `templates/` (HTML pages) and `static/` (CSS and college logo).
- `backend/app.py` contains the Flask routes, authentication, OD approval workflow, and SQLite database logic.
- `requirements.txt` lists Python dependencies.
- `Procfile` and `render.yaml` are deployment configuration examples.

## Run locally
1. Install Python 3.10+.
2. Open a terminal in this project folder.
3. Run `pip install -r requirements.txt`.
4. Run `python app.py`.
5. Open `http://127.0.0.1:5000`.

The database file is created automatically as `digital_od.sqlite3` for local use.

## Workflow
Student submits an OD request -> assigned Adviser accepts/rejects -> only an accepted request is forwarded to HOD -> HOD makes the final decision. The dashboards show request history.

## Important deployment note
The Render configuration uses a persistent disk mounted at `/var/data` for SQLite storage. Keep that disk attached to preserve records across restarts/redeployments. Set a strong `SECRET_KEY` and replace the demo registration password and reset PIN with secure production mechanisms before real institutional use. The current shared registration password and reset PIN are demo conveniences, not production-grade security.
