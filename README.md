# ElasticOps Agent

> **Elasticsearch security-log search and operational analytics, with an inspectable workflow.**

ElasticOps Agent gives security and operations teams one place to investigate Elasticsearch events, review service errors, and check cluster health. Ask a question in plain language, inspect the evidence returned by Elasticsearch, and follow the workflow that produced the response.

The application pairs a React and TypeScript dashboard with a FastAPI service and an Elasticsearch-backed LangGraph workflow. A supervisor routes each request to hybrid keyword-and-vector search or to analytics and cluster-health checks; a report writer turns the returned evidence into a concise briefing. Validated log batches are embedded and indexed for later retrieval. The workflow supports human investigation by presenting evidence and suggested follow-up; it does not automatically remediate incidents.

## Contents

- [Capabilities](#capabilities)
- [System design](#system-design)
- [Technology stack](#technology-stack)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
  - [Requirements](#requirements)
  - [Run locally](#run-locally)
  - [Run with Docker Compose](#run-with-docker-compose)
- [API reference](#api-reference)
- [Authentication and production configuration](#authentication-and-production-configuration)
- [Tests and build](#tests-and-build)
- [License](#license)

## Capabilities

| Capability | Description |
| --- | --- |
| Security-event investigation | Search indexed events with Elasticsearch keyword and vector retrieval combined using reciprocal rank fusion (RRF). |
| Operational analytics | Run Elasticsearch aggregations, including error counts grouped by service. |
| Cluster health | Inspect cluster health or, for Elasticsearch Serverless, endpoint and index availability. |
| Inspectable workflow | View the selected specialist, workflow trace, execution timing, and matching records. |
| Log ingestion | Validate and normalize batches of up to 100 events, create embeddings, and index them. |
| Exportable briefings | Export the latest assistant response as a Markdown report. |

## System design

### Containerized architecture

```text
 Browser: React + TypeScript UI
                 |
                 | /api
                 v
       Nginx: static UI + API proxy
                 |
                 v
        FastAPI: auth, validation, API
                 |
                 v
       LangGraph supervisor/router
            /               \
   search request      analytics or health
          |                    |
          v                    v
   Threat specialist   Compliance specialist
   keyword + vector    aggregations + health
            \               /
             v             v
                Report writer
                     |
                     v
           Response, results, and trace

 Specialists ---------------------------> Elasticsearch
 Log ingestion API -> embeddings -------> Elasticsearch
```

In the containerized setup, Nginx serves the frontend and reverse-proxies `/api` requests to FastAPI. The API connects to Elasticsearch. In local development, Vite serves the frontend and proxies `/api` directly to the local FastAPI server.

### Query lifecycle

1. The browser sends a natural-language request to the FastAPI query endpoint. Pydantic validates it, and production deployments enforce the configured query authentication.
2. The LangGraph supervisor classifies the request and creates a validated payload for one specialist. Search requests go to the threat specialist; analytics and cluster-health requests go to the compliance specialist.
3. The selected specialist queries Elasticsearch. Search requests use hybrid keyword and vector retrieval. Analytics requests run Elasticsearch aggregations; health requests check cluster health or, for Serverless, endpoint and index availability.
4. The writer formats the returned evidence into a concise report. The API returns the report with the route, workflow trace, execution timings, and relevant search or analytics data.

The agents are nodes in one sequential LangGraph workflow, not separate services communicating over an agent protocol. Routing selects one specialist per request; the specialists do not run in parallel. The workflow is deterministic and does not call a generative language model.

### Hybrid retrieval and RRF

The threat specialist combines two Elasticsearch result lists: a lexical `multi_match` query (BM25) over security-event fields and a k-nearest-neighbor query against 384-dimensional vectors. The vectors are generated on CPU by `sentence-transformers/all-MiniLM-L6-v2`. Elasticsearch's reciprocal rank fusion (RRF) retriever merges the rankings using a rank window of 50 and `rank_constant` of 60, then returns up to 10 records.

If the Elasticsearch deployment rejects native RRF because it is unavailable under its license, the application runs the lexical and vector searches separately and merges their ranked results locally with the reciprocal-rank formula.

### Indexing and ingestion

At API startup, the service connects to Elasticsearch and prepares the `enterprise_security_logs` index. Its strict mapping stores event timestamps, severity, service and host identifiers, optional security fields, log messages, and 384-dimensional dense vectors. In development, sample events are seeded into an empty index by default; production seeding defaults to off.

The ingestion endpoint accepts batches of 1–100 validated events. It normalizes supported event fields, embeds each log message, and bulk-indexes the event and vector into the same index used for retrieval. Elasticsearch is an external dependency; Docker Compose does not start it.

### Deployment and trust boundaries

Elasticsearch credentials belong in the API's protected environment and must not be exposed to the browser. Production requires HTTPS and an Elasticsearch API key. Query access supports a configured API key or an authenticated browser session, while ingestion uses its own API key. Configure ingress TLS, network restrictions, credential storage, and Elasticsearch operations separately for your deployment.

## Technology stack

| Area | Technologies |
| --- | --- |
| Web application | React 18, TypeScript, Vite 6 |
| Styling and icons | Tailwind CSS 4, Lucide React |
| API | Python 3.10, FastAPI, Pydantic 2, Uvicorn |
| Workflow orchestration | LangGraph with validated Pydantic workflow contracts |
| Search and storage | Elasticsearch 8 Python client; Elasticsearch index and aggregations |
| Embeddings | Sentence Transformers through LangChain Community `HuggingFaceEmbeddings`, using `sentence-transformers/all-MiniLM-L6-v2` |
| Configuration | `python-dotenv` |
| Web serving and containers | Nginx, Docker, Docker Compose |
| Tests and CI | Python `unittest`, FastAPI `TestClient`/HTTPX, TypeScript checks, GitHub Actions |

Frontend dependencies are declared in `package.json` and locked in `package-lock.json`. Backend dependencies and supported version ranges are declared in `requirements.txt`.

## Project structure

```text
.
├── .github/
│   └── workflows/
│       └── ci.yml
├── app/
│   ├── __init__.py
│   ├── core_engine.py       # Elasticsearch, embeddings, workflow, and reports
│   └── main.py              # FastAPI routes, authentication, and validation
├── src/
│   ├── components/
│   │   ├── ChatPanel.tsx
│   │   ├── Header.tsx
│   │   ├── LoginModal.tsx
│   │   ├── LogsModal.tsx
│   │   └── TimelinePanel.tsx
│   ├── data/
│   │   └── constants.ts
│   ├── types/
│   │   ├── auth.ts
│   │   └── index.ts
│   ├── App.tsx
│   ├── index.css
│   └── main.tsx
├── tests/
│   └── test_core_engine.py
├── .dockerignore
├── .gitignore
├── docker-compose.yml
├── Dockerfile
├── index.html
├── LICENSE
├── nginx.conf
├── package.json
├── package-lock.json
├── README.md
├── requirements.txt
├── tsconfig.json
└── vite.config.ts
```

The local `.env` file is Git-ignored and is not included in the tree. Generated output, installed dependencies, and caches such as `dist/`, `node_modules/`, `.venv/`, `.pytest_cache/`, and `__pycache__/` are also excluded.

## Getting started

### Requirements

- Python 3.10
- Node.js 22 and npm
- An Elasticsearch endpoint reachable by the API
- Docker and Docker Compose for the containerized setup

Elasticsearch is required for the backend to start: the API connects to it and prepares the `enterprise_security_logs` index. The embedding model is downloaded on first use when embeddings are needed.

### Run locally

Start Elasticsearch separately, then configure the root `.env` file:

```env
APP_ENV=development
ELASTICSEARCH_URL=http://localhost:9200
ELASTICSEARCH_API_KEY=
ELASTICOPS_SEED_SAMPLE_DATA=true
```

In development, sample data seeding defaults to enabled and only occurs when the index is empty. Set `ELASTICOPS_SEED_SAMPLE_DATA=false` to disable it.

Install dependencies from the project root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
npm ci
```

Start the backend and frontend in separate terminals. Activate `.venv` in the backend terminal if needed.

**Terminal 1 — FastAPI backend**

```powershell
.\.venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Confirm that the API is ready at [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health).

**Terminal 2 — React frontend**

```powershell
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). Vite proxies `/api` requests to FastAPI on port `8000`.

### Run with Docker Compose

Docker Compose starts the complete application frontend and API as two containers. It does **not** start Elasticsearch. Provide a reachable production Elasticsearch endpoint and set the variables listed under [Authentication and production configuration](#authentication-and-production-configuration) in your shell or root `.env` file before starting.

```powershell
docker compose up --build -d
docker compose ps
```

Open [http://localhost](http://localhost). The `web` service waits for the API health check to pass.

```powershell
docker compose logs -f api
docker compose down
```

## API reference

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Check API availability. |
| `GET` | `/api/v1/auth/status` | Check whether a browser session is required. |
| `POST` | `/api/v1/auth/login` | Create a browser session in configured production mode. |
| `POST` | `/api/v1/agent/query` | Run a search, analytics, or cluster-health workflow. |
| `POST` | `/api/v1/logs/ingest` | Validate, embed, and index a batch of log events. |

FastAPI's interactive API documentation is available at `/docs` when the API is running.

### Submit an investigation query

In development mode, query authentication is disabled by default:

```powershell
$body = @{
  user_query = "Find failed login events for the identity service"
  context = @{}
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/agent/query" `
  -ContentType "application/json" `
  -Body $body
```

The response includes the report, selected route, workflow trace, execution records, search results, analytics, and cluster health.

### Ingest log events

A request can contain up to 100 events. Each event requires `service`, either `level` or `severity`, and either `message` or `log_message`. The timestamp is optional and defaults to the current UTC time.

```powershell
$body = @{
  events = @(
    @{
      timestamp = "2026-10-08T12:00:00Z"
      level = "ERROR"
      service = "checkout-api"
      node = "checkout-01"
      status_code = 503
      latency_ms = 1200
      trace_id = "trace-example-1"
      message = "Upstream database request timed out"
    }
  )
} | ConvertTo-Json -Depth 5

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/api/v1/logs/ingest" `
  -ContentType "application/json" `
  -Body $body
```

When `ELASTICOPS_INGEST_API_KEY` is configured, send it in the `X-API-Key` header. Production mode requires this key.

## Authentication and production configuration

Development mode is the default and does not require query or browser-login credentials. In production, the query endpoint accepts either the configured `X-API-Key` or a valid `elasticops_session` cookie. The browser sign-in flow requires `ELASTICOPS_QUERY_USERNAME`, `ELASTICOPS_QUERY_PASSWORD`, and `ELASTICOPS_QUERY_SESSION_SECRET`; the HTTP-only session cookie expires after eight hours. Log ingestion uses its separate `ELASTICOPS_INGEST_API_KEY`.

For production, provide the following values through a secret manager or protected deployment environment. Docker Compose reads variables from the shell or the root `.env` file:

```env
APP_ENV=production
ELASTICSEARCH_URL=https://elasticsearch.example.com:9200
ELASTICSEARCH_API_KEY=<elasticsearch-api-key>
ELASTICSEARCH_CA_CERTS=
ELASTICOPS_QUERY_API_KEY=<query-api-key>
ELASTICOPS_INGEST_API_KEY=<ingestion-api-key>
ELASTICOPS_QUERY_SESSION_SECRET=<long-random-secret>
ELASTICOPS_QUERY_USERNAME=<operator-username>
ELASTICOPS_QUERY_PASSWORD=<strong-operator-password>
ELASTICOPS_SEED_SAMPLE_DATA=false
```

Production Elasticsearch connections must use HTTPS and an API key. Set `ELASTICSEARCH_CA_CERTS` when a custom CA certificate is needed. Keep real credentials out of source control; `.env` is ignored by Git. Configure TLS termination, access controls, monitoring, and backups before exposing the application. Do not expose Elasticsearch port 9200 publicly.

## Tests and build

Run the backend tests and the frontend type-check/build:

```powershell
python -m unittest discover -s tests -v
npm ci
npm run build
```

The GitHub Actions workflow runs the backend tests and frontend build on pushes and pull requests.

## License

This project is licensed under the [MIT License](LICENSE).
