# CyberGuard 🛡️

**CyberGuard** — веб-сервіс для аудиту безпеки сайтів за стандартом **OWASP TOP-10**.

> Легкий аналог Nessus / OWASP ZAP для школярів і малого бізнесу

## Концепція

Користувач вводить URL → система паралельно запускає 5 сканерів → рахує рівень ризику 0-100 → видає дашборд і PDF-звіт з інструкціями як виправити.

## Архітектура

```
[Користувач] -> [Frontend] -> [FastAPI Backend] -> [Черга задач]
                                           |
              +------------------------------------------------+
              |              |              |                  |
         [Headers Scanner] [SSL Scanner] [Ports Scanner] [XSS/SQLi Scanner]
              |              |              |                  |
              +----------------> [Aggregator + Risk Engine] <---+
                                   |           |
                             [SQLite/JSON] [PDF Generator]
                                   |
                              [Frontend Dashboard]
```

Всі сканери працюють паралельно через `asyncio.gather()` — сканування займає 8-15 сек замість 60.

## Структура проекту

```
/cyberguard/
├── backend/
│   ├── main.py              # FastAPI, ендпоінти /scan, /result/{id}
│   ├── models.py            # Pydantic моделі
│   ├── risk_engine.py       # Логіка підрахунку балів ризику
│   ├── report.py            # Генерація PDF через fpdf2
│   ├── database.py          # SQLite - історія сканувань
│   └── scanners/
│       ├── headers.py       # Перевірка CSP, HSTS, X-Frame-Options
│       ├── ssl_check.py     # Перевірка сертифіката, TLS
│       ├── ports.py         # Перевірка відкритих портів через socket
│       ├── xss.py           # Пошук XSS через BeautifulSoup
│       └── sqli.py          # Пошук SQLi через аналіз помилок БД
├── frontend/
│   ├── index.html
│   ├── dashboard.html
│   ├── history.html
│   ├── style.css
│   └── app.js
├── requirements.txt
└── README.md
```

## Швидкий старт

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
# Відкрий http://localhost:8000
```

Frontend працює як статика через FastAPI або окремо на Vercel.

## API

| Метод | Шлях | Опис |
|-------|------|------|
| POST | `/api/scan` | Запустити сканування `{ "url": "https://example.com" }` |
| GET | `/api/result/{scan_id}` | Отримати результат |
| GET | `/api/history` | Історія сканувань |
| GET | `/api/report/{scan_id}` | Завантажити PDF звіт |
| GET | `/api/health` | Health check |

## Система оцінки ризику

| Рівень | Бали | Приклад |
|--------|------|---------|
| LOW | 5 | Відсутній X-Content-Type-Options |
| MEDIUM | 15 | Відсутній HSTS, відкритий порт 22 |
| HIGH | 25 | XSS, SQLi, прострочений SSL |

- 0-30 → LOW 🟢
- 31-69 → MEDIUM 🟡
- 70-100 → HIGH 🔴

## Технології

- **Backend:** Python 3.10+, FastAPI, requests, beautifulsoup4, fpdf2
- **Frontend:** HTML/CSS/JS + Chart.js
- **БД:** SQLite
- **Хостинг:** Render (бекенд) + Vercel (фронтенд)

## ⚠️ Ethical Use Disclaimer

> **Використовуйте CyberGuard лише на сайтах, на які маєте дозвіл!**
> Несканований аудит чужих сайтів без згоди власника може порушувати законодавство (ст. 361 ККУ, CFAA). 
> Інструмент призначений виключно для навчальних цілей та аудиту власних ресурсів. Автори не несуть відповідальності за неправомірне використання.
>
> Дозволені цілі для тестів: `testphp.vulnweb.com`, `juice-shop`, `dvwa`, власні локальні проекти.

## Ліцензія

MIT
