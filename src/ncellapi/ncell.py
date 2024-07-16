import logging
import sqlite3
from pathlib import Path
from typing import Any, Callable, Dict, Tuple, TypeVar, cast
from urllib.parse import urljoin

import requests
from pydantic import ValidationError

from ncellapi.models.balance import QueryBalanceResponse
from ncellapi.models.credentials import NcellCredentials
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
    """
    Decorator to check if the user is logged in before executing the wrapped function.

    Parameters:
        func (T): The function to be wrapped.

    Returns:
        T: The wrapped function.
    """

    def wrapper(self: "Ncell", *args: Any, **kwargs: Any) -> Any:
        if not self._is_logged_in:
            return NcellResponse(status="error", message="User not logged in")
        return func(self, *args, **kwargs)

    return cast(T, wrapper)


class Ncell(NcellAPI):
    def __init__(self, msisdn: int, password: str):
        """
        Initializes the Ncell object with the provided MSISDN and password.

        Parameters:
            msisdn (int): The MSISDN number.
            password (str): The password associated with the MSISDN.

        Returns:
            None
        """
        try:
            credentials = NcellCredentials(msisdn=msisdn, password=password)
        except ValidationError as e:
            raise ValueError(
                f"Invalid credentials: {e.errors(include_url=False, include_context=False, include_input=False)}"
            )
        super().__init__()
        self._session = requests.Session()
        self._msisdn = credentials.msisdn
        self._password = credentials.password
        self._username = str(self._msisdn)
        self._is_logged_in = False

        package_dir = Path(__file__).parent
        db_file = package_dir / "cache.db"
        self._db_connection = sqlite3.connect(db_file, check_same_thread=False)
        self._create_table()

    def _create_table(self) -> None:
        """
        Creates a table named 'ncell' in the database if it doesn't already exist.

        This function uses the `_db_connection` attribute to execute a SQL query that
        creates a table named 'ncell' with the following columns:
        - 'id' (INTEGER): The primary key of the table.
        - 'session_id' (TEXT): The session ID.
        - 'token_id' (TEXT): The token ID.
        - 'created_at' (DATETIME): The timestamp of when the row was created.
        - 'updated_at' (DATETIME): The timestamp of when the row was last updated.

        Parameters:
            None.

        Returns:
            None.
        """
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
        """
        Saves the session ID and token ID to the database.

        This function inserts a new row into the 'ncell' table with the provided session ID and token ID.
        If a row with the same ID already exists, it updates the session ID and token ID columns with the new values.

        Parameters:
            session_id (str): The session ID to be saved.
            token_id (str): The token ID to be saved.

        Returns:
            None
        """
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

    def _get_ids_from_db(self) -> Tuple[str | None, str | None]:
        """
        Retrieves the session ID and token ID from the database for the given MSISDN.

        This function executes a SQL query to retrieve the session ID and token ID from the 'ncell' table
        where the ID matches the provided MSISDN. If a row is found, it returns a tuple containing the session ID
        and token ID. If no row is found, it returns a tuple with None values.

        Returns:
            Tuple[str | None, str | None]: A tuple containing the session ID and token ID, or None values if no row is found.
        """
        cursor = self._db_connection.cursor()
        cursor.execute(
            """SELECT session_id, token_id FROM ncell WHERE id=?""", (self._msisdn,)
        )
        row = cursor.fetchone()
        if row:
            session_id, token_id = row
            return session_id, token_id
        return None, None

    def _post_request(self, endpoint: str, data: Dict[str, Any]) -> requests.Response:
        """
        Sends a POST request to the specified endpoint with the provided data.

        Args:
            endpoint (str): The endpoint to send the request to.
            data (Dict): The data payload to be sent with the request.

        Returns:
            requests.Response: The response object from the POST request.
        """
        try:
            return self._session.post(
                url=urljoin(self._base_url, endpoint), headers=self._headers, json=data
            )
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {e}")
            raise NetworkError(f"Error in network request: {e}")

    def check_login_status(self) -> bool:
        """
        Check the login status by retrieving session ID and token ID from the database.
        If session ID or token ID is missing, return False.
        Send a POST request to the '/api/system/isLogin' endpoint with the generated signcode.
        If the response is not okay, log the error and return False.
        Parse the response data and validate it using the LoginCheckResponse model.
        If the validation fails or the resultCode is not 0, update headers and return False.
        Set the '_is_logged_in' flag to True and return True if login is successful.

        Returns:
            bool: True if login is successful, False otherwise.
        """
        session_id, token_id = self._get_ids_from_db()
        if not session_id or not token_id:
            return False
        endpoint = "/api/system/isLogin"
        self._update_headers(
            {
                "SESSION-ID": session_id,
                "TOKEN-ID": token_id,
                "signcode": generate_signcode(session_id, endpoint, token_id, {}),
            }
        )
        res = self._post_request(endpoint, {})
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
            self._update_headers({"SESSION-ID": "", "TOKEN-ID": ""})
            return False
        self._is_logged_in = True
        return True

    def login(self) -> NcellResponse:
        """
        Logs in the user with the provided username and password.

        Returns:
            NcellResponse: The response object containing the status, message, and data of the login attempt.
                - If the user is already logged in, returns a success message with the existing user session.
                - If the login attempt is successful, saves the session ID and token ID to the database,
                  updates the headers with the new session ID and token ID, and returns a success message
                  with the logged in customer's name.
                - If the login attempt fails, returns an error message with the corresponding error code
                  and description from the server response.
                - If there is an error during the validation of the server response, returns an error message
                  with the validation errors.
                - If there is an error during the login request, returns an error message with the error text.
        """
        if self.check_login_status():
            return NcellResponse(
                status="success", message="Using existing user session"
            )

        endpoint = "/api/login/loginWithSmsOrPWD"
        self._login_json_data.update(
            {"ACC_NBR": self._username, "LOGIN_CODE": self._password}
        )
        self._update_headers(
            {"signcode": generate_signcode("", endpoint, "", self._login_json_data)}
        )
        res = self._post_request(endpoint, data=self._login_json_data)
        if res.ok:
            try:
                data = res.json()
                login_data = LoginResponse(**data)
            except ValidationError as e:
                logger.error(f"Validation error: {e.errors()}")
                errors = e.errors(include_url=False, include_input=False)
                errors.insert(0, SERVER_RESPONSE_VALIDATION_ERROR)
                return NcellResponse(
                    status="error",
                    message="Failed to validate login response",
                    errors=errors,
                )
            except ValueError:
                logger.error("Invalid JSON response")
                return NcellResponse(
                    status="error", message="Invalid login JSON response"
                )

            if int(login_data.resultCode) == 0:
                self._save_ids_to_db(
                    login_data.result.SESSION_ID, login_data.result.TOKEN_ID
                )
                self._is_logged_in = True
                self._update_headers(
                    {
                        "SESSION-ID": login_data.result.SESSION_ID,
                        "TOKEN-ID": login_data.result.TOKEN_ID,
                    }
                )
                return NcellResponse(
                    status="success",
                    message=f"Logged in as {login_data.result.CUST_NAME}",
                    data=login_data,
                )
            return NcellResponse(
                status="error",
                message=login_data.resultDesc,
                data=login_data,
            )
        try:
            error_message = res.json()
        except ValueError:
            error_message = res.text
        return NcellResponse(status="error", message=error_message)

    @login_required
    def balance(self) -> NcellResponse:
        """
        Retrieves the balance of the user's account.

        This method sends a POST request to the `/api/billing/queryAcctBal` endpoint to retrieve the balance of the user's account. It requires the user to be logged in.

        Returns:
            NcellResponse: A response object containing the status, message, and data of the balance retrieval. The status can be "success" or "error". The message provides information about the outcome of the balance retrieval. The data contains the balance information.

        Note:
            This function requires the user to be logged in.
        """
        endpoint = "/api/billing/queryAcctBal"
        self._update_headers(
            {
                "signcode": generate_signcode(
                    self._headers["SESSION-ID"],
                    endpoint,
                    self._headers["TOKEN-ID"],
                    {},
                )
            }
        )
        res = self._post_request(endpoint, {})
        return self._handle_response(res, QueryBalanceResponse, "Balance retrieved")

    @login_required
    def usage_detail(self) -> NcellResponse:
        """
        Retrieves the usage detail of the user.

        This function sends a POST request to the `/api/billing/qryUsageDetail` endpoint to retrieve the usage detail of the user.
        It first updates the headers with the necessary information, including the `SESSION-ID`, `TOKEN-ID`, and the `signcode` generated using the `generate_signcode` function.
        Then, it sends the request using the `post_request` method and handles the response using the `_handle_response` method.

        Returns:
            NcellResponse: The response object containing the usage detail.

        Note:
            This function requires the user to be logged in.
        """
        endpoint = "/api/billing/qryUsageDetail"
        self._update_headers(
            {
                "signcode": generate_signcode(
                    self._headers["SESSION-ID"],
                    endpoint,
                    self._headers["TOKEN-ID"],
                    {},
                )
            }
        )
        res = self._post_request(endpoint, {})
        return self._handle_response(res, UsageDetailResponse, "Usage detail retrieved")

    @login_required
    def sms_count(self) -> NcellResponse:
        """
        Retrieves the count of SMS that can be sent by the user.

        This function sends a POST request to the `/api/system/sendSMSRestCount` endpoint to retrieve the count of SMS that can be sent by the user.
        It first updates the headers with the necessary information, including the `SESSION-ID`, `TOKEN-ID`, and the `signcode` generated using the `generate_signcode` function.
        Then, it sends the request using the `post_request` method and handles the response using the `_handle_response` method.

        Returns:
            NcellResponse: The response object containing the count of SMS that can be sent.

        Note:
            This function requires the user to be logged in.
        """
        endpoint = "/api/system/sendSMSRestCount"
        self._update_headers(
            {
                "signcode": generate_signcode(
                    self._headers["SESSION-ID"],
                    endpoint,
                    self._headers["TOKEN-ID"],
                    {},
                )
            }
        )
        res = self._post_request(endpoint, {})
        return self._handle_response(res, SMSCountResponse, "SMS count retrieved")

    @login_required
    def validate_sms(
        self, recipient_mssidn: int, message: str, send_time: str = ""
    ) -> NcellResponse:
        """
        Validates an SMS message for sending to a recipient MSISDN.
        This function sends a POST request to the `/api/system/validate4SendSMS` endpoint with the provided recipient MSISDN, message, and optional send time.
        It validates the input payload using the `SMSPayload` model and handles validation errors by returning an error response.
        The function updates the request headers with a signcode generated based on the session ID, endpoint, token ID, and payload.
        After sending the request and receiving a response, it processes the validation result and returns an appropriate response object based on the validation outcome.

        Parameters:
            recipient_mssidn (int): The recipient's MSISDN number.
            message (str): The message content to be sent.
            send_time (str, optional): The scheduled time for sending the SMS.

        Returns:
            NcellResponse: The response object containing the validation result of the SMS.

        Note:
            This function requires the user to be logged in.
        """
        endpoint = "/api/system/validate4SendSMS"
        payload = {"ACC_NBR": recipient_mssidn, "MSG": message, "SEND_TIME": send_time}

        try:
            payload = SMSPayload(**payload).model_dump()
        except ValidationError as e:
            logger.error(f"Validation error: {e.errors()}")
            return NcellResponse(
                status="error",
                message="Failed to validate SMS payload",
                errors=e.errors(include_url=False, include_input=False),
            )

        self._update_headers(
            {
                "signcode": generate_signcode(
                    self._headers["SESSION-ID"],
                    endpoint,
                    self._headers["TOKEN-ID"],
                    payload,
                )
            }
        )
        res = self._post_request(endpoint, payload)
        if res.ok:
            data = res.json()
            try:
                validate_sms_response = SMSValidationResponse(**data)
            except ValidationError as e:
                logger.error(f"Validation error: {e.errors()}")
                errors = e.errors(include_url=False, include_input=False)
                errors.insert(0, SERVER_RESPONSE_VALIDATION_ERROR)
                return NcellResponse(
                    status="error",
                    message="Failed to validate SMS validation response",
                    errors=errors,
                )
            if (
                int(validate_sms_response.resultCode) == 0
                and int(validate_sms_response.result.CODE) == 0
            ):
                return NcellResponse(
                    status="success",
                    message="SMS validation successful",
                    data=validate_sms_response,
                )
            if validate_sms_response.result is not None:
                return NcellResponse(
                    status="error",
                    message=validate_sms_response.result.DESC,
                    data=validate_sms_response.result,
                )
        else:
            try:
                error_message = res.json()
            except ValueError:
                error_message = res.text
            return NcellResponse(status="error", message=error_message)

    @login_required
    def send_sms(
        self, recipient_mssidn: int, message: str, send_time: str = ""
    ) -> NcellResponse:
        """
        Sends an SMS to the specified recipient with the given message.

        Args:
            recipient_mssidn (int): The MSISDN number of the recipient.
            message (str): The message to be sent.
            send_time (str, optional): The time to send the SMS. Defaults to "".

        Returns:
            NcellResponse: A response object indicating the status of the SMS sending operation.
                The response object has the following attributes:
                - status (str): The status of the operation. Possible values are "success" or "error".
                - message (str): A message describing the status of the operation.
                - data (Dict): Additional data related to the operation.

        Note:
            This function requires the user to be logged in.

        Example:
            >>> ncell = Ncell(9876543210, "strongpwd")
            >>> ncell.login()
            >>> response = ncell.send_sms(1234567890, "Hello, world!")
            >>> print(response.status)
            success
            >>> print(response.message)
            SMS sent successfully
        """
        validation_response = self.validate_sms(recipient_mssidn, message, send_time)

        if validation_response.status != "success":
            return validation_response

        endpoint = "/api/system/sendSMS"
        payload = {"ACC_NBR": recipient_mssidn, "MSG": message, "SEND_TIME": send_time}

        # try:
        #     payload = SMSPayload(**payload).model_dump()
        # except ValidationError as e:
        #     logger.error(f"Validation error: {e.errors()}")
        #     return NcellResponse(
        #         status="error",
        #         message="Failed to validate SMS payload",
        #         errors=e.errors(include_url=False, include_input=False),
        #     )

        self._update_headers(
            {
                "signcode": generate_signcode(
                    self._headers["SESSION-ID"],
                    endpoint,
                    self._headers["TOKEN-ID"],
                    payload,
                )
            }
        )
        res = self._post_request(endpoint, payload)
        return self._handle_response(res, SMSSendResponse, "SMS sent successfully")

    def _handle_response(
        self, res: requests.Response, model: type[BaseResponse], success_message: str
    ) -> NcellResponse:
        """
        Handles the response from the server and returns a NcellResponse object.

        Args:
            res (requests.Response): The response object from the server.
            model (type[BaseResponse]): The model class to use for deserializing the response data.
            success_message (str): The success message to include in the NcellResponse object.

        Returns:
            NcellResponse: The NcellResponse object containing the status, message, and data of the response.
                - If the response is not successful, returns an error message with the corresponding error code
                  and description from the server response.
                - If there is a validation error during deserialization, returns an error message with the validation
                  errors.
                - If the result code is 0, returns a success message with the data from the response.
                - Otherwise, returns an error message with the result description from the response.

        """
        if not res.ok:
            try:
                error_message = res.json()
            except ValueError:
                error_message = res.text
            logger.error(f"Error from server: {error_message}")
            return NcellResponse(status="error", message=error_message)

        try:
            data = res.json()
            response_data = model(**data)
        except ValidationError as e:
            logger.error(f"Validation error: {e.errors()}")

            errors = e.errors(include_url=False, include_input=False)
            errors.insert(0, SERVER_RESPONSE_VALIDATION_ERROR)
            return NcellResponse(
                status="error", message="Failed to validate response", errors=errors
            )
        except ValueError:
            logger.error("Invalid JSON response")
            return NcellResponse(
                status="error", message="Invalid JSON response from server"
            )

        if not isinstance(response_data, model):
            return NcellResponse(
                status="error",
                message="Failed to deserialize response data",
                errors=[SERVER_RESPONSE_VALIDATION_ERROR],
            )

        if int(response_data.resultCode) == 0:
            return NcellResponse(
                status="success",
                message=success_message,
                data=response_data,
            )

        return NcellResponse(
            status="error",
            message=response_data.resultDesc,
            data=response_data,
        )
