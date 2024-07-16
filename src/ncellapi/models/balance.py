from typing import List, Optional

from pydantic import BaseModel, Field


class PointList(BaseModel):
    POINT_BAL: str
    POINT_TYPE: str


class Result(BaseModel):
    DATA_BAL: str
    LOCAL_CONSUME_BAL: str
    LOCAL_BAL: str
    SMS_BAL: int
    POINT_LIST: List[PointList]


class QueryBalanceResponse(BaseModel):
    result: Optional[Result] = Field(default=None)
    resultCode: str
    resultDesc: str
