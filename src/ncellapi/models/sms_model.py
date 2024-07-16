from pydantic import BaseModel, Field
from typing_extensions import Annotated


class SMSCountResponse(BaseModel):
    result: int | None = Field(..., default=None)
    resultCode: str
    resultDesc: str


class SMSPayload(BaseModel):
    ACC_NBR: Annotated[int, Field(strict=False)]
    MSG: Annotated[str, Field(strict=True, min_length=3, max_length=160)]
    SEND_TIME: str | None


class ValidationResult(BaseModel):
    CODE: str
    DESC: str
    IS_NCELL_FLAG: str | None = Field(default=None)


class SMSValidationResponse(BaseModel):
    resultCode: str
    resultDesc: str
    result: ValidationResult | None = Field(default=None)


class SMSSendResponse(BaseModel):
    resultCode: str
    resultDesc: str
