# SENTINELMAIL — Phishing Email Detector Dashboard

Enterprise-grade SOC-style web application that analyzes suspicious emails using AI (Google Gemini or OpenAI GPT-4o) and presents a full threat intelligence dashboard.

## Features

- Paste raw email (headers + body) or upload `.eml` files
- AI-powered phishing analysis with 6 indicator categories
- Animated threat gauge, progress bars, and SOC dark theme UI
- Scan history with shareable URLs (`/scan/<uuid>/`)
- Stats bar: total scans, average threat score, phishing caught today
- Export analysis as JSON, copy report, share link
- Real-time analysis via Fetch API (no full page reload on submit)
- Dark/light theme toggle

## Quick Start

### 1. Create virtual environment (recommended)

```bash
cd "PBL 4 SEM"
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment

Copy `.env.example` to `.env` and set your API key:

```env
SECRET_KEY=your-django-secret-key
DEBUG=True
GEMINI_API_KEY=your-gemini-api-key-here
# OPENAI_API_KEY=optional-openai-key
AI_PROVIDER=gemini
```

> Without an API key, the app runs in **heuristic demo mode** so you can test the UI locally.

### 4. Run migrations

```bash
python manage.py migrate
```

### 5. Start the server

```bash
python manage.py runserver
```

Visit **http://127.0.0.1:8000**

## Project Structure

```
PBL 4 SEM/
├── manage.py
├── requirements.txt
├── .env.example
├── phishing_detector/     # Django project settings
├── detector/              # Main app
│   ├── models.py          # EmailScan model
│   ├── views.py           # Analyze, results, history
│   ├── ai_engine.py       # Gemini / OpenAI integration
│   ├── email_parser.py    # Email parsing & link extraction
│   └── templates/
└── static/
    ├── css/dashboard.css
    └── js/app.js
```

## API Keys

| Provider | Env Variable       | Model              |
|----------|--------------------|--------------------|
| Gemini   | `GEMINI_API_KEY`   | gemini-1.5-flash   |
| OpenAI   | `OPENAI_API_KEY`   | gpt-4o             |

Set `AI_PROVIDER=gemini` or `AI_PROVIDER=openai` in `.env`.

## Production Notes

- Set `DEBUG=False` and a strong `SECRET_KEY`
- Switch database to PostgreSQL in `settings.py`
- Use `gunicorn` + `nginx` behind HTTPS
- Never commit `.env` to version control

## License

MIT — portfolio / educational use.
