from pydantic import BaseModel
from fastmcp import FastMCP
import os

class DocumentRequest(BaseModel):
    tenant_id: str
    document_id: str


class DocumentResult(BaseModel):
    tenant_id: str
    document_id: str
    value: str


mcp = FastMCP(
    name="Stateless MCP Governance Router",
    instructions="A minimal stateless MCP router exposing curated tenant-scoped tools.",
)

DOCUMENTS = {
    ("tenant-a", "doc-001"): "Example document for Tenant A.",
    ("tenant-b", "doc-001"): "Example document for Tenant B.",
}

@mcp.tool
def read_document(request: DocumentRequest) -> DocumentResult:
    """Read a tenant-scoped document value."""
    key = (request.tenant_id, request.document_id)

    if key not in DOCUMENTS:
        raise ValueError("Document not found.")

    return DocumentResult(
        tenant_id=request.tenant_id,
        document_id=request.document_id,
        value=DOCUMENTS[key],
    )

if __name__ == "__main__":
    host = os.getenv("MCP_HOST", "127.0.0.1")
    port = int(os.getenv("MCP_PORT", "8000"))

    mcp.run(
        transport="http",
        host=host,
        port=port,
        stateless_http=True,
    )