from typing import Any


class NcellResponse:
    def __init__(self, status: str, message: str, data: dict[str, Any] | None = None):
        self.status = status
        self.message = message
        self.data = data

    def to_dict(self):
        return {
            "status": self.status,
            "message": self.message,
            "data": self.data,
        }

    def __repr__(self) -> str:
        return f"<NcellResponse status={self.status} message={self.message}>"
