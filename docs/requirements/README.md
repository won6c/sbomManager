# Requirements

## Runtime Requirements
- Python 3.10+
- FastAPI / Uvicorn
- Pydantic
- Loguru
- requests / python-dotenv
- pyelftools for ELF analysis
- psutil for process/network inspection
- networkx for graph-oriented correlation
- pytest for validation

Install backend dependencies:

```bash
pip install -r requirements.txt
```

## Frontend Requirements
- Node.js / npm
- React + Vite
- Tailwind/CSS frontend assets under `src/web/frontend/`

```bash
cd src/web/frontend
npm install
npm run dev
```

## Operational Constraints
- Binary scanning must remain path-limited.
- Non-root probe gaps must become explicit restricted evidence instead of hard failures.
- External intelligence providers are network/rate-limit dependent; cache results under `memory/data/`.
