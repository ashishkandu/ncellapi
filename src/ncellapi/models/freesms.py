from pydantic import BaseModel


class SMSCountResponse(BaseModel):
    result: int
    resultCode: str
    resultDesc: str
