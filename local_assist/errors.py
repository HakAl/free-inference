from __future__ import annotations


class LocalAssistError(Exception):
    """Structured failure surfaced to MCP clients."""

    def __init__(self, code: str, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_payload(self) -> dict:
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


class EndpointUnavailable(LocalAssistError):
    pass


class ModelUnavailable(LocalAssistError):
    pass


class ModelMismatch(LocalAssistError):
    pass


class ModelOutputMalformed(LocalAssistError):
    pass


class ModelTimeout(LocalAssistError):
    pass

