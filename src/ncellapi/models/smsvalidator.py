from pydantic import BaseModel, Field
from typing_extensions import Annotated


class SMSPayload(BaseModel):
    ACC_NBR: Annotated[int, Field(strict=False)]
    MSG: Annotated[str, Field(strict=True, min_length=3, max_length=160)]
    SEND_TIME: str | None


class ValidationResult(BaseModel):
    CODE: str
    DESC: str
    IS_NCELL_FLAG: str | None


class SMSValidationResponse(BaseModel):
    resultCode: str
    resultDesc: str
    result: ValidationResult


class SMSSendResponse(BaseModel):
    resultCode: str
    resultDesc: str
