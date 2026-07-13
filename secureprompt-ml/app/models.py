from pydantic import BaseModel, Field
from typing import List


class NerRequest(BaseModel):
    text: str = Field(..., max_length=32768)


class NerEntity(BaseModel):
    entity_type: str
    start: int
    end: int
    score: float
    text: str
    compliance_categories: List[str]


class NerResponse(BaseModel):
    entities: List[NerEntity]


class InjectionRequest(BaseModel):
    text: str = Field(..., max_length=2048)


class InjectionResponse(BaseModel):
    is_injection: bool
    score: float


class EmbedRequest(BaseModel):
    text: str = Field(..., max_length=32768)


class EmbedResponse(BaseModel):
    embedding: List[float]


class RagCheckRequest(BaseModel):
    text: str = Field(..., max_length=32768)
    workspace_id: str = Field(
        ...,
        description="Workspace UUID — used as mandatory Qdrant payload filter",
    )


class RagCheckMatch(BaseModel):
    rule_id: str
    score: float


class RagCheckResponse(BaseModel):
    matches: List[RagCheckMatch]
    is_match: bool


class ScanFileEntity(BaseModel):
    text: str
    label: str
    score: float


class ScanFileResponse(BaseModel):
    pii_found: bool
    secrets_found: bool
    injection_detected: bool
    entities: List[ScanFileEntity]
    redacted_text: str | None = None
    file_size_bytes: int
    preview_truncated: bool
    # Reversible {{Type_N}} token -> original PII value, so the chat gateway can
    # restore the file's PII in the model's response (vault-preload). Empty when
    # nothing was redacted.
    token_map: dict[str, str] = {}


class ScanTaskCreated(BaseModel):
    task_id: str


class ScanTaskStatus(BaseModel):
    status: str  # running | done | error
    result: ScanFileResponse | None = None
    error: str | None = None


class SecureTaskCreated(BaseModel):
    task_id: str


class SecureSummary(BaseModel):
    entities_count: int
    types: dict[str, int]
    pages: int
    ocr_used: bool
    output_mime: str
    output_filename: str


class SecureTaskStatus(BaseModel):
    status: str  # running | done | error
    summary: SecureSummary | None = None
    error: str | None = None
