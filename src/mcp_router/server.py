import time

from fastmcp import Context, FastMCP
from pydantic import BaseModel
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .approvals import ApprovalError, ApprovalStore, verify_webhook
from .audit import AuditSink
from .containment import EgressPolicy, PathPolicy

from .disclosure import DisclosureMiddleware
from .enforcement import TokenEnforcementMiddleware
from .ingress_guard import IngressGuardMiddleware
from .jwks_cache import RemoteJwks
from .registry import CORE, EXTENDED, ToolRegistry, ToolSpec
from .revocation_cache import RevocationCache
from .scope_guard import ScopeGuardMiddleware
from .settings import Settings, get_settings


class DocumentRequest(BaseModel):
    tenant_id: str
    document_id: str


class DocumentResult(BaseModel):
    tenant_id: str
    document_id: str
    value: str


class SummaryRequest(BaseModel):
    tenant_id: str


class SummaryResult(BaseModel):
    tenant_id: str
    document_count: int


class FileRequest(BaseModel):
    path: str


class FileResult(BaseModel):
    path: str
    text: str


class AskRequest(BaseModel):
    question: str


class AskResult(BaseModel):
    answer: str


class PurgeRequest(BaseModel):
    tenant_id: str
    document_id: str


class PurgeResult(BaseModel):
    status: str
    document_id: str
    request_id: str | None = None


SAMPLE_DOCUMENTS = {
    ("tenant-a", "doc-001"): "Example document for Tenant A.",
    ("tenant-b", "doc-001"): "Example document for Tenant B.",
}


class DocumentStore:
    """Stand-in for the real backing store. One instance per app, not per module."""

    def __init__(self, documents: dict[tuple[str, str], str] | None = None) -> None:
        self._documents = dict(documents if documents is not None else SAMPLE_DOCUMENTS)

    def get(self, tenant_id: str, document_id: str) -> str:
        key = (tenant_id, document_id)
        if key not in self._documents:
            raise ValueError("Document not found.")
        return self._documents[key]

    def count(self, tenant_id: str) -> int:
        return sum(1 for tenant, _ in self._documents if tenant == tenant_id)

    def delete(self, tenant_id: str, document_id: str) -> None:
        self._documents.pop((tenant_id, document_id), None)


def make_read_document(store: DocumentStore):
    def read_document(request: DocumentRequest) -> DocumentResult:
        """Read a tenant-scoped document value."""
        return DocumentResult(
            tenant_id=request.tenant_id,
            document_id=request.document_id,
            value=store.get(request.tenant_id, request.document_id),
        )

    return read_document


def make_summarize_documents(store: DocumentStore):
    def summarize_documents(request: SummaryRequest) -> SummaryResult:
        """Count the documents a tenant can see."""
        return SummaryResult(tenant_id=request.tenant_id, document_count=store.count(request.tenant_id))

    return summarize_documents


def make_read_text(policy: PathPolicy):
    def read_text(request: FileRequest) -> FileResult:
        """Read a text file from inside the configured roots."""
        target = policy.resolve(request.path)
        if not target.is_file():
            raise ValueError("Not a readable file.")
        return FileResult(path=str(target), text=target.read_text()[:4096])

    return read_text


async def sample_text(ctx: Context, prompt: str) -> str:
    result = await ctx.sample(prompt)
    text = getattr(result, "text", None)
    return text if isinstance(text, str) else str(result)


def make_ask_model():
    async def ask_model(request: AskRequest, ctx: Context) -> AskResult:
        """Answer a question using the client's sampling capability."""
        return AskResult(answer=await sample_text(ctx, request.question))

    return ask_model


def make_purge_document(store: DocumentStore, approvals: ApprovalStore, sink: AuditSink | None = None):
    def purge_document(request: PurgeRequest) -> PurgeResult:
        """Delete a document, but only after a human approved this exact request."""
        arguments = request.model_dump()

        if not approvals.consume("documents.purge_document", arguments):
            request_id = approvals.create_pending("documents.purge_document", arguments)
            if sink is not None:
                sink.write("approval_requested", tool="documents.purge_document", request_id=request_id)
            return PurgeResult(status="approval_required", document_id=request.document_id, request_id=request_id)

        store.delete(request.tenant_id, request.document_id)
        if sink is not None:
            sink.write("approval_consumed", tool="documents.purge_document", tenant_id=request.tenant_id)
        return PurgeResult(status="purged", document_id=request.document_id)

    return purge_document


def build_registry(
    settings: Settings | None = None,
    approvals: ApprovalStore | None = None,
    sink: AuditSink | None = None,
) -> ToolRegistry:
    settings = settings or get_settings()
    approvals = approvals or ApprovalStore(settings.approvals_db)
    path_policy = PathPolicy(settings.roots)
    egress_policy = EgressPolicy(settings.egress_allowlist)  # wired into outbound tools
    store = DocumentStore()
    registry = ToolRegistry()
    registry.register(
        ToolSpec(
            name="documents.read_document",
            namespace="documents",
            scope="mcp:documents:read",
            description="Read a tenant-scoped document value.",
            input_model=DocumentRequest,
            result_model=DocumentResult,
            handler=make_read_document(store),
            tier=CORE,
        )
    )
    registry.register(
        ToolSpec(
            name="reports.summarize_documents",
            namespace="reports",
            scope="mcp:reports:read",
            description="Count the documents visible to a tenant.",
            input_model=SummaryRequest,
            result_model=SummaryResult,
            handler=make_summarize_documents(store),
            tier=EXTENDED,
        )
    )
    registry.register(
        ToolSpec(
            name="files.read_text",
            namespace="files",
            scope="mcp:files:read",
            description="Read a text file from inside the configured roots.",
            input_model=FileRequest,
            result_model=FileResult,
            handler=make_read_text(path_policy),
            tier=EXTENDED,
        )
    )
    registry.register(
        ToolSpec(
            name="reports.ask_model",
            namespace="reports",
            scope="mcp:reports:read",
            description="Answer a question through the client's sampling capability.",
            input_model=AskRequest,
            result_model=AskResult,
            handler=make_ask_model(),
            tier=EXTENDED,
        )
    )
    registry.register(
        ToolSpec(
            name="documents.purge_document",
            namespace="documents",
            scope="mcp:documents:write",
            description="Delete a document after human approval.",
            input_model=PurgeRequest,
            result_model=PurgeResult,
            handler=make_purge_document(store, approvals, sink),
            tier=EXTENDED,
            requires_approval=True,
        )
    )
    return registry


def build_server(registry: ToolRegistry) -> FastMCP:
    mcp = FastMCP(
        name="Stateless MCP Governance Router",
        instructions="A stateless MCP router exposing curated tenant-scoped tools.",
    )

    for spec in registry.all():
        mcp.tool(name=spec.name, description=spec.description)(spec.handler)

    mcp.add_middleware(DisclosureMiddleware(registry))
    return mcp


def build_app(
    settings: Settings | None = None,
    *,
    key_set=None,
    revocations=None,
    tool_registry: ToolRegistry | None = None,
    approvals: ApprovalStore | None = None,
    sink: AuditSink | None = None,
):
    settings = settings or get_settings()
    sink = sink or AuditSink(settings.audit_path)
    approvals = approvals or ApprovalStore(settings.approvals_db)
    tool_registry = tool_registry or build_registry(settings, approvals, sink)
    key_set = key_set or RemoteJwks(settings.jwks_uri, settings.jwks_cache_seconds)
    revocations = revocations or RevocationCache(f"{settings.issuer_url}/revoked")

    mcp_app = build_server(tool_registry).http_app(transport="http", stateless_http=True)

    async def approve(request):
        request_id = request.path_params["request_id"]
        body = await request.body()

        try:
            verify_webhook(
                body,
                request.headers.get("x-approval-signature", ""),
                request.headers.get("x-approval-timestamp", ""),
                settings.approval_hmac_secret,
            )
        except ApprovalError as exc:
            sink.write("approval_rejected", request_id=request_id, reason=exc.code)
            return JSONResponse({"error": exc.code}, status_code=401)

        try:
            approvals.approve(request_id)
        except ApprovalError as exc:
            sink.write("approval_replay", request_id=request_id, reason=exc.code)
            return JSONResponse({"error": exc.code}, status_code=409)

        sink.write("approval_granted", request_id=request_id)
        return JSONResponse({"status": "approved", "request_id": request_id})

    return Starlette(
        routes=[
            Route("/approvals/{request_id}", approve, methods=["POST"]),
            Mount("/", app=mcp_app),
        ],
        lifespan=mcp_app.lifespan,
        middleware=[
            Middleware(
                IngressGuardMiddleware,
                allowed_hosts=settings.allowed_hosts,
                allowed_origins=settings.allowed_origins,
            ),
            Middleware(
                TokenEnforcementMiddleware,
                settings=settings,
                key_set=key_set,
                revocations=revocations,
                audit=sink.write,
            ),
            Middleware(ScopeGuardMiddleware, registry=tool_registry, audit=sink.write),
        ],
    )


def main() -> None:
    import uvicorn

    settings = get_settings()
    uvicorn.run(build_app(settings), host=settings.mcp_host, port=settings.mcp_port)


if __name__ == "__main__":
    main()