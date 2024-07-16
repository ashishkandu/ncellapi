import hashlib
import json
import re
from typing import Any, Dict, Optional


def generate_signcode(
    session_id: str, url: str, token_id: str, data: Optional[Dict[str, Any]] = None
):
    """
    Generates the signcode based on the provided session_id, url, token_id, and data.
    Args:
        session_id (str): The SESSION-ID from session storage.
        url (str): The request URL.
        token_id (str): The TOKEN-ID from session storage.
        data (Dict, optional): The request data.

    Returns:
        str: The generated signcode.
    """
    secret = "16BytesString"
    if data is not None and bool(data):
        data_str = json.dumps(data)
        data_str = re.sub(r"[^a-zA-Z\d]", "", data_str)
        data_str = data_str.replace("null", "")
        base_string = session_id + url + data_str + token_id + secret
    else:
        base_string = session_id + url + token_id + secret
    return hashlib.sha256(base_string.encode("utf-8")).hexdigest()
