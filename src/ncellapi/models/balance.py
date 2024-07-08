from typing import List

from pydantic import BaseModel


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
    result: Result | None = None
    resultCode: str
    resultDesc: str
