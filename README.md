# Stateless MCP Governance Router

A minimal, stateless Model Context Protocol (MCP) router built with FastMCP, exposing a curated tenant-scoped tool over HTTP.

The project is the foundation for a production-grade agentic infrastructure layer where agents can discover and execute controlled tools without relying on server-side session state.

> **Current scope — Stair 23:** Stateless FastMCP HTTP server, one typed tenant-scoped tool, Pydantic request/response contracts, MCP Inspector verification, and HTTP GET → 405 protection.

---

## Why This Project Exists

Agentic systems need more than an LLM.

An agent can reason about **what action should be taken**, but it needs tools to interact with external systems and data.

MCP provides a standardized protocol for exposing those capabilities.

This project focuses on the protocol boundary between an agent and its tools:

Agent
  ↓
MCP Router
  ↓
Curated Tool
  ↓
Enterprise Resource

The router is intentionally stateless so that requests do not depend on previous in-memory server sessions.

That makes the service easier to scale horizontally behind a load balancer because any healthy instance can handle an incoming request.

---

## Architecture

Mermaid architecture:

flowchart LR
    Agent[Agent / MCP Client]
        -->|HTTP MCP request| Router[FastMCP Stateless Router]

    Router
        -->|tools/call| Tool[read_document]

    Tool
        -->|tenant_id + document_id| Store[(Mock Document Store)]

    Tool
        -->|Pydantic structured result| Router

    Router
        -->|MCP response| Agent

### Request flow

1. An MCP client sends a request to the HTTP MCP endpoint.
2. FastMCP receives and processes the MCP request.
3. The client can discover the available tool through `tools/list`.
4. The client executes `read_document` through `tools/call`.
5. The tool receives a typed `DocumentRequest`.
6. The tool performs a tenant/document lookup.
7. The tool returns a typed `DocumentResult`.
8. FastMCP serializes the result into the MCP response.

---

## Stateless Design

The server runs FastMCP with `stateless_http=True`.

Stateless HTTP means the server does not depend on a persistent in-memory MCP session between requests.

Conceptually:

Stateful server

Client A
   ↓
Load Balancer
   ↓
Server 1
   ↓
Session stored in Server 1 memory

Future request
   ↓
Must potentially return to Server 1

With a stateless server:

Client A
   ↓
Load Balancer
   ├──→ Server 1
   ├──→ Server 2
   └──→ Server 3

Each request contains the information required for the server to process it.

This model is better suited to horizontal scaling because requests can be distributed across multiple healthy instances without depending on a particular server's in-memory session state.

---

## HTTP Transport and GET → 405

The MCP endpoint is:

http://127.0.0.1:8000/mcp

The server accepts MCP requests through HTTP `POST`.

A direct `GET /mcp` request is rejected with:

HTTP/1.1 405 Method Not Allowed

Verified response body:

Method Not Allowed

The 405 response is enforced by the HTTP framework rather than by a custom application route.

This prevents an unsupported GET request from being treated as an MCP operation.

---

## Tool Contract

Stair 23 exposes one deliberately small tool:

`read_document`

The input contract is defined using Pydantic:

class DocumentRequest(BaseModel):
    tenant_id: str
    document_id: str

The output contract is also defined using Pydantic:

class DocumentResult(BaseModel):
    tenant_id: str
    document_id: str
    value: str

The resulting MCP input shape is:

{
  "request": {
    "tenant_id": "tenant-a",
    "document_id": "doc-001"
  }
}

The structured result is:

{
  "tenant_id": "tenant-a",
  "document_id": "doc-001",
  "value": "Example document for Tenant A."
}

### Tenant scoping

The tool uses the pair:

`tenant_id + document_id`

as the lookup key.

For Stair 23, the backing store is intentionally a small in-memory mock:

("tenant-a", "doc-001")
("tenant-b", "doc-001")

This demonstrates the tenant-scoped contract without pretending that production database authorization has already been implemented.

---

## Project Structure

stateless-mcp-governance-router/
├── .env.example
├── pyproject.toml
├── README.md
└── src/
    └── mcp_router/
        ├── __init__.py
        └── server.py

### Important files

| File | Purpose |
|---|---|
| `pyproject.toml` | Project metadata, Python requirement, runtime dependency, and package/build configuration |
| `.env.example` | Safe template for local environment configuration |
| `src/mcp_router/server.py` | FastMCP server, typed models, tool, and HTTP server startup |
| `README.md` | Architecture, design decisions, verification evidence, and project roadmap |

---

## Technology Stack

- Python 3.13
- FastMCP 4.x
- Pydantic
- HTTP transport
- Uvicorn through FastMCP's HTTP serving path
- MCP Inspector
- `pyproject.toml` + setuptools
- VS Code development workflow

---

## Local Setup

### 1. Create the virtual environment

This project requires Python 3.11 or newer.

Example:

/opt/homebrew/opt/python@3.13/bin/python3.13 -m venv .venv

Activate it:

source .venv/bin/activate

Verify:

python --version

Expected:

Python 3.13.x

---

### 2. Install the project

Install the project in editable mode:

python -m pip install -e .

Editable installation allows the local source code to be used directly while developing the project.

---

### 3. Start the server

python -m mcp_router.server

The default local endpoint is:

http://127.0.0.1:8000/mcp

The host and port can be configured through:

MCP_HOST
MCP_PORT

---

## MCP Verification

The implementation was verified through the actual MCP HTTP endpoint.

### Server startup

Verified:

FastMCP 4.0.3
Starting MCP server 'Stateless MCP Governance Router'
with transport 'http' (stateless)
on http://127.0.0.1:8000/mcp

---

### MCP initialization

`initialize` returned:

HTTP/1.1 200 OK

The server reported:

protocolVersion: 2025-06-18
serverInfo.name: Stateless MCP Governance Router

---

### Tool discovery

`tools/list` returned:

HTTP/1.1 200 OK

The server exposed exactly one tool:

`read_document`

The MCP response included both an input schema and an output schema.

---

### Tool execution

The following tenant-scoped request was executed:

{
  "request": {
    "tenant_id": "tenant-a",
    "document_id": "doc-001"
  }
}

The MCP response returned:

{
  "tenant_id": "tenant-a",
  "document_id": "doc-001",
  "value": "Example document for Tenant A."
}

The response contained:

`isError: false`

---

### GET → 405

Direct request:

curl -i http://127.0.0.1:8000/mcp

Verified:

HTTP/1.1 405 Method Not Allowed

Response body:

Method Not Allowed

---

## MCP Inspector Verification

The project was connected to MCP Inspector using:

Transport: streamable-http
URL: http://127.0.0.1:8000/mcp

The Inspector successfully connected to the local MCP server.

The Inspector CLI was then used to execute the actual tool:

npx @modelcontextprotocol/inspector --cli \
  http://127.0.0.1:8000/mcp \
  --transport http \
  --method tools/call \
  --tool-name read_document \
  --tool-args-json '{"request":{"tenant_id":"tenant-a","document_id":"doc-001"}}' \
  --format json

Verified result:

{
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"tenant_id\":\"tenant-a\",\"document_id\":\"doc-001\",\"value\":\"Example document for Tenant A.\"}"
      }
    ],
    "structuredContent": {
      "tenant_id": "tenant-a",
      "document_id": "doc-001",
      "value": "Example document for Tenant A."
    },
    "isError": false
  }
}

This confirms that the tool can be executed through the MCP protocol using an MCP client/tooling layer rather than only by directly calling Python code.

---

## Verification Checklist

- [x] Project scaffold created
- [x] Python 3.13 virtual environment created
- [x] `pyproject.toml` validated
- [x] Editable project installation succeeded
- [x] FastMCP installed successfully
- [x] Stateless HTTP server starts successfully
- [x] MCP `/mcp` endpoint verified
- [x] `initialize` request verified
- [x] `tools/list` verified
- [x] Exactly one curated tool exposed
- [x] Pydantic input contract verified
- [x] Pydantic output contract verified
- [x] `tools/call` verified through raw MCP HTTP
- [x] Tenant-scoped document lookup verified
- [x] `GET /mcp` → HTTP 405 verified
- [x] MCP Inspector connection verified
- [x] MCP Inspector CLI tool execution verified
- [ ] OAuth 2.1
- [ ] Authorization / scoped delegation
- [ ] Additional enterprise tools
- [ ] MCP05 schema hardening
- [ ] Immutable audit logging
- [ ] Host/origin protection
- [ ] Tool sandbox / egress controls
- [ ] Progressive Disclosure
- [ ] OWASP MCP Top 10 hardening
- [ ] AWS ECS Fargate deployment

---

## Security Scope

Security hardening is intentionally **not implemented in Stair 23**.

The current implementation demonstrates the protocol and architectural foundation only.

There is currently:

- no OAuth authentication
- no authorization layer
- no production identity provider
- no persistent database
- no production tenant authorization policy
- no immutable audit sink
- no SSRF protection
- no tool sandbox
- no progressive-disclosure mechanism
- no OWASP MCP Top 10 hardening layer

These capabilities are introduced in later build stages.

---

## Roadmap

### Stair 24 — OAuth 2.1 / AuthPlane

Planned:

- OAuth 2.1
- RFC 7523 Ed25519 authentication
- short-lived tokens
- tool-scoped authorization
- no Dynamic Client Registration
- HostOriginGuard

### Stair 25 — Curated Tools

Planned:

- enterprise-oriented tools
- typed tool registry
- controlled tool exposure
- namespace governance

### Stair 26 — MCP05 Schema Hardening

Planned:

- stricter Pydantic contracts
- schema pinning
- validation against unsafe tool definitions

### Stairs 27–29 — Governance, Testing and Hardening

Planned:

- immutable OTel audit sink
- 405 ASGI protection
- HostOriginGuard
- deny-by-default sandbox / egress controls
- MCP Inspector test harness
- Progressive Disclosure
- quantified token-economy benchmark
- OWASP MCP Top 10 hardening
- final technical README and freeze

---

## Production Deployment

### Target

AWS ECS Fargate

The project is intentionally designed as a standalone service and will be deployed independently from the other portfolio projects.

Deployment work is **not part of Stair 23**.

AWS Load Balancer
       ↓
ECS Fargate
       ↓
FastMCP Stateless Router
       ↓
Governed Tools

Production infrastructure, authentication, authorization, observability, and security controls will be added in later Stairs.

---

## Portfolio Positioning

**Portfolio theme:**

> Production-Grade Agentic Infrastructure

This project represents the **MCP perimeter / tool-access layer** of the portfolio.

The goal is to demonstrate that an agentic system can be given standardized tool access while progressively adding:

Stateless MCP
      ↓
Authentication
      ↓
Authorization
      ↓
Schema Governance
      ↓
Auditability
      ↓
Sandboxing
      ↓
Progressive Disclosure
      ↓
Production Deployment

---

## Loom Demo

### Planned 2-minute walkthrough

**0:00–0:25 — Problem**

Explain why agents need standardized and controlled access to external tools.

**0:25–0:50 — Architecture**

Show:

Agent → Stateless MCP Router → Tool

Explain why stateless HTTP is useful for horizontally scalable services.

**0:50–1:20 — Live MCP execution**

Show MCP Inspector connecting to:

http://127.0.0.1:8000/mcp

Execute:

`read_document`

and show the structured response.

**1:20–1:40 — HTTP protection**

Show:

GET /mcp
→ 405 Method Not Allowed

**1:40–2:00 — Roadmap**

Explain how later Stairs add OAuth, authorization, schema governance, audit logging, sandboxing, and Progressive Disclosure.

### Loom

> TODO — record after Stair 23 freeze.

---

## Current Status

**Stair 23 — Build**

Status:

> **Implementation and local verification complete; Git commit/push and final Stair 23 freeze pending.**

Current build demonstrates:

- Stateless FastMCP HTTP serving
- One typed tenant-scoped tool
- Pydantic request/response contracts
- MCP protocol discovery
- MCP tool execution
- HTTP 405 behavior
- MCP Inspector verification

The project does **not** yet claim production security or deployment.

---

## License

Private portfolio project during development.

The repository will be made public after deployment and portfolio preparation.