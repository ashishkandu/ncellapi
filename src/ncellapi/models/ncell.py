from typing import Any, Dict, List, Literal, Optional, Protocol

from pydantic import BaseModel


class NcellResponse:
    """
    A class to represent a response from the Ncell API.

    Attributes:
        status (Literal["success", "error"]): The status of the response.
        message (str): The message associated with the response.
        data (Optional[BaseModel]): The data associated with the response.
        errors (Optional(List[Dict[str, Any]])): The list of errors associated with the response.
    """

    def __init__(
        self,
        status: Literal["success", "error"],
        message: str,
        data: Optional[BaseModel] = None,
        errors: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.status = status
        self.message = message
        self.data = data
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the response object to a dictionary.

        Returns:
            Dict[str, Any]: The response as a dictionary.
        """
        response_dict = {
            "status": self.status,
            "message": self.message,
            "data": self.data.model_dump() if self.data else {},
            "errors": self.errors,
        }
        return response_dict

    def __repr__(self) -> str:
        """
        Return a string representation of the response object.

        Returns:
            str: The string representation of the response object.
        """
        return (
            f"<NcellResponse(status={self.status!r}, message={self.message!r}, "
            f"data={self.data.__class__.__name__ if self.data else None!r}, "
            f"errors={len(self.errors) if self.errors else 0!r})>"
        )


class BaseResponse(Protocol):
    """
    A protocol to represent a base response with common attributes.
    """

    resultCode: str
    resultDesc: str

    def model_dump(self) -> Dict[str, Any]: ...
