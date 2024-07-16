from pydantic import BaseModel, Field


class Item(BaseModel):
    ACCT_RES_ID: str
    EXP_DATE: str
    GROSS_BAL: str | float
    CONSUME_BAL: str | float
    UNIT_NAME: str
    REAL_BAL: str | float
    ACCT_RES_NAME: str


class UsageDetailResponse(BaseModel):
    result: dict[str, list[Item] | dict] | None = Field(..., default=None)
    resultCode: str
    resultDesc: str
