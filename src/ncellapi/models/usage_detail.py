from typing import Dict, List, Optional, Union

from pydantic import BaseModel, Field


class Item(BaseModel):
    ACCT_RES_ID: str
    EXP_DATE: str
    GROSS_BAL: Union[str, float]
    CONSUME_BAL: Union[str, float]
    UNIT_NAME: str
    REAL_BAL: Union[str, float]
    ACCT_RES_NAME: str


class UsageDetailResponse(BaseModel):
    result: Optional[Union[Dict[str, List[Item]], Dict]] = Field(default=None)
    resultCode: str
    resultDesc: str
