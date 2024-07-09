import re

from pydantic import BaseModel, Field, field_validator


class NcellCredentials(BaseModel):
    msisdn: int = Field(..., description="The MSISDN number")
    password: str = Field(
        ...,
        min_length=5,
        max_length=26,
        description="The password associated with the MSISDN",
    )

    @field_validator("msisdn")
    def validate_msisdn(cls, value):
        msisdn_str = str(value)
        # Normalize the MSISDN number by removing the 977 prefix if present
        if msisdn_str.startswith("977") and len(msisdn_str) == 13:
            msisdn_str = msisdn_str[3:]
        if not re.match(r"^[9][6-9]\d{8}$", msisdn_str):
            raise ValueError("MSISDN must be a valid Nepali number")
        return int(msisdn_str)
