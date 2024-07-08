from pydantic import BaseModel


class Item(BaseModel):
    ACCT_RES_ID: str
    EXP_DATE: str
    GROSS_BAL: str
    CONSUME_BAL: str
    UNIT_NAME: str
    REAL_BAL: str
    ACCT_RES_NAME: str


class Result(BaseModel):
    data: list[Item] | dict


class UsageDetailResponse(BaseModel):
    result: dict[str, list[Item] | dict]
    resultCode: str
    resultDesc: str
