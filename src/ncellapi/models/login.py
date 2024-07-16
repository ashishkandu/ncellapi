from typing import Optional

from pydantic import BaseModel, Field


class Result(BaseModel):
    UPDATE_DATE: str
    VALID: str
    ACC_NBR: str
    CUST_NAME: str
    SESSION_ID: str = Field(alias="SESSION-ID")
    TOKEN_ID: str


class LoginResponse(BaseModel):
    resultCode: str
    resultDesc: str
    result: Optional[Result] = Field(default=None)


class LoginCheckResponse(BaseModel):
    resultCode: str
    resultDesc: str
