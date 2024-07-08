import logging
import sqlite3
from pathlib import Path
from typing import Any, Callable, TypeVar, cast
from urllib.parse import urljoin

import requests
from pydantic import ValidationError

from ncellapi.models.balance import QueryBalanceResponse
from ncellapi.models.login import LoginCheckResponse, LoginResponse
from ncellapi.models.ncell import BaseResponse, NcellResponse
from ncellapi.models.sms_model import (
    SMSCountResponse,
    SMSPayload,
    SMSSendResponse,
    SMSValidationResponse,
)
from ncellapi.models.usage_detail import UsageDetailResponse
from ncellapi.ncell_api import NcellAPI
from ncellapi.signcode import generate_signcode

SERVER_RESPONSE_VALIDATION_ERROR = {"reason": "Invalid response from server"}


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ncellapi")


class NetworkError(Exception):
    pass


T = TypeVar("T", bound=Callable[..., Any])


def login_required(func: T) -> T:
    def wrapper(self: "Ncell", *args: Any, **kwargs: Any) -> Any:
        if not self._is_logged_in:
            return NcellResponse(status="error", message="User not logged in")
        return func(self, *args, **kwargs)

    return cast(T, wrapper)


class Ncell(NcellAPI):
    def __init__(self, msisdn: int, password: str):
        super().__init__()
        self._session = requests.Session()
        self._msisdn = msisdn
        self._password = password
        self._username = str(msisdn)
        self._is_logged_in = False

        package_dir = Path(__file__).parent
        db_file = package_dir / "cache.db"
        self._db_connection = sqlite3.connect(db_file, check_same_thread=False)
        # self._cursor = self._db_connection.cursor()
        self.create_table()

    def create_table(self) -> None:
        with self._db_connection:
            self._db_connection.execute(
                """CREATE TABLE IF NOT EXISTS ncell (
                id INTEGER PRIMARY KEY, 
                session_id TEXT, 
                token_id TEXT, 
                
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP, 
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )"""
            )

    def _save_ids_to_db(self, session_id: str, token_id: str) -> None:
        with self._db_connection:
            self._db_connection.execute(
                """INSERT INTO ncell (id, session_id, token_id, created_at, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(id) DO UPDATE SET 
                session_id=excluded.session_id, 
                token_id=excluded.token_id, 
                updated_at=CURRENT_TIMESTAMP;""",
                (self._msisdn, session_id, token_id),
            )

    def _get_ids_from_db(self) -> tuple[str | None, str | None]:
        cursor = self._db_connection.cursor()
        cursor.execute(
            """SELECT session_id, token_id FROM ncell WHERE id=?""", (self._msisdn,)
        )
        row = cursor.fetchone()
        if row:
            session_id, token_id = row
            return session_id, token_id
        return None, None

    def post_request(self, endpoint: str, data: dict[str, Any]) -> requests.Response:
        try:
            return self._session.post(
                url=urljoin(self.base_url, endpoint), headers=self.headers, json=data
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {e}")
            raise NetworkError(f"Error in network request: {e}")

    def check_login_status(self) -> bool:
        session_id, token_id = self._get_ids_from_db()
        if not session_id or not token_id:
            return False
        endpoint = "/api/system/isLogin"
        self.update_headers(
            {
                "SESSION-ID": session_id,
                "TOKEN-ID": token_id,
                "signcode": generate_signcode(session_id, endpoint, token_id, {}),
            }
        )
        res = self.post_request(endpoint, {})
        if not res.ok:
            logger.error(f"Unable to login. Error from server: {res.text}")
            return False

        data = res.json()
        try:
            login_check_response = LoginCheckResponse(**data)
        except ValidationError as e:
            logger.error(f"Validation error: {e.errors()}")
            return False
        if int(login_check_response.resultCode) != 0:
            self.update_headers({"SESSION-ID": "", "TOKEN-ID": ""})
            return False
        self._is_logged_in = True
        return True

    def login(self) -> NcellResponse:
        if self.check_login_status():
            return NcellResponse("success", "Using existing user session")

        endpoint = "/api/login/loginWithSmsOrPWD"
        self.login_json_data.update(
            {"ACC_NBR": self._username, "LOGIN_CODE": self._password}
        )
        self.update_headers(
            {"signcode": generate_signcode("", endpoint, "", self.login_json_data)}
        )
        res = self.post_request(endpoint, data=self.login_json_data)
        if res.ok:
            data = res.json()
            try:
                login_data = LoginResponse(**data)
            except ValidationError as e:
                logger.error(f"Validation error: {e.errors()}")
                errors = e.errors(include_url=False, include_input=False)
                errors.insert(0, SERVER_RESPONSE_VALIDATION_ERROR)
                return NcellResponse(status="error", message=errors, data=data)

            if int(login_data.resultCode) == 0:
                self._save_ids_to_db(
                    login_data.result.SESSION_ID, login_data.result.TOKEN_ID
                )
                self._is_logged_in = True
                self.update_headers(
                    {
                        "SESSION-ID": login_data.result.SESSION_ID,
                        "TOKEN-ID": login_data.result.TOKEN_ID,
                    }
                )
                return NcellResponse(
                    status="success",
                    message=f"Logged in as {login_data.result.CUST_NAME}",
                    data=login_data.model_dump(),
                )
            return NcellResponse(
                status="error",
                message=login_data.resultDesc,
                data=login_data.model_dump(),
            )
        return NcellResponse(status="error", message="Login failed", data=res.text)

    @login_required
    def balance(self) -> NcellResponse:
        endpoint = "/api/billing/queryAcctBal"
        self.update_headers(
            {
                "signcode": generate_signcode(
                    self.headers["SESSION-ID"],
                    endpoint,
                    self.headers["TOKEN-ID"],
                    {},
                )
            }
        )
        res = self.post_request(endpoint, {})
        return self._handle_response(res, QueryBalanceResponse, "Balance retrieved")

    @login_required
    def usage_detail(self) -> NcellResponse:
        endpoint = "/api/billing/qryUsageDetail"
        self.update_headers(
            {
                "signcode": generate_signcode(
                    self.headers["SESSION-ID"],
                    endpoint,
                    self.headers["TOKEN-ID"],
                    {},
                )
            }
        )
        res = self.post_request(endpoint, {})
        return self._handle_response(res, UsageDetailResponse, "Usage detail retrieved")

    @login_required
    def sms_count(self) -> NcellResponse:
        endpoint = "/api/system/sendSMSRestCount"
        self.update_headers(
            {
                "signcode": generate_signcode(
                    self.headers["SESSION-ID"],
                    endpoint,
                    self.headers["TOKEN-ID"],
                    {},
                )
            }
        )
        res = self.post_request(endpoint, {})
        return self._handle_response(res, SMSCountResponse, "SMS count retrieved")

    @login_required
    def validate_sms(
        self, recipient_mssidn: int, message: str, send_time: str = ""
    ) -> NcellResponse:
        endpoint = "/api/system/validate4SendSMS"
        payload = {"ACC_NBR": recipient_mssidn, "MSG": message, "SEND_TIME": send_time}

        try:
            payload = SMSPayload(**payload).model_dump()
        except ValidationError as e:
            logger.error(f"Validation error: {e.errors()}")
            return NcellResponse(
                status="error",
                message=e.errors(include_url=False, include_input=False),
            )

        self.update_headers(
            {
                "signcode": generate_signcode(
                    self.headers["SESSION-ID"],
                    endpoint,
                    self.headers["TOKEN-ID"],
                    payload,
                )
            }
        )
        res = self.post_request(endpoint, payload)
        if res.ok:
            data = res.json()
            try:
                validate_sms_response = SMSValidationResponse(**data)
            except ValidationError as e:
                logger.error(f"Validation error: {e.errors()}")
                errors = e.errors(include_url=False, include_input=False)
                errors.insert(0, SERVER_RESPONSE_VALIDATION_ERROR)
                return NcellResponse(status="error", message=errors, data=data)
            if int(validate_sms_response.result.CODE) == 0:
                return NcellResponse(
                    status="success",
                    message="SMS validation successful",
                    data=validate_sms_response.model_dump(),
                )
            return NcellResponse(
                status="error",
                message=validate_sms_response.result.DESC,
                data=validate_sms_response.result.model_dump(),
            )

        return NcellResponse(
            status="error", message="Failed to validate SMS", data=res.json()
        )

    @login_required
    def send_sms(
        self, recipient_mssidn: int, message: str, send_time: str = ""
    ) -> NcellResponse:
        validation_response = self.validate_sms(recipient_mssidn, message, send_time)

        if validation_response.status != "success":
            return validation_response

        endpoint = "/api/system/sendSMS"
        payload = {"ACC_NBR": recipient_mssidn, "MSG": message, "SEND_TIME": send_time}

        try:
            payload = SMSPayload(**payload).model_dump()
        except ValidationError as e:
            logger.error(f"Validation error: {e.errors()}")
            return NcellResponse(
                status="error",
                message=e.errors(include_url=False, include_input=False),
            )

        self.update_headers(
            {
                "signcode": generate_signcode(
                    self.headers["SESSION-ID"],
                    endpoint,
                    self.headers["TOKEN-ID"],
                    payload,
                )
            }
        )
        res = self.post_request(endpoint, payload)
        return self._handle_response(res, SMSSendResponse, "SMS sent successfully")

    def _handle_response(
        self, res: requests.Response, model: type[BaseResponse], success_message: str
    ) -> NcellResponse:
        if not res.ok:
            logger.error(f"Error from server: {res.text}")
            return NcellResponse(
                status="error", message="Request failed", data=res.text
            )

        data = res.json()
        try:
            response_data = model(**data)
        except ValidationError as e:
            logger.error(f"Validation error: {e.errors()}")

            errors = e.errors(include_url=False, include_input=False)
            errors.insert(0, SERVER_RESPONSE_VALIDATION_ERROR)
            return NcellResponse(status="error", message=errors, data=data)

        if int(response_data.resultCode) == 0:
            return NcellResponse(
                status="success",
                message=success_message,
                data=response_data.model_dump(),
            )

        return NcellResponse(
            status="error",
            message=response_data.resultDesc,
            data=response_data.model_dump(),
        )
