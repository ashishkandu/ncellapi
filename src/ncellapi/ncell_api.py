class NcellAPI:
    def __init__(self):
        self.base_url = "https://customer.ncell.com.np"
        self.headers = {
            "Accept": "*/*",
            "Accept-Language": "en",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "x-requested-with,content-type",
            "Access-Control-Allow-Origin": "*",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Content-Type": "application/json;charset=UTF-8",
            "Origin": "https://customer.ncell.com.np",
            "Pragma": "no-cache",
            "Referer": "https://customer.ncell.com.np/",
            "SESSION-ID": "",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "TOKEN-ID": "",
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "X-Requested-With": "XMLHttpRequest",
            "sec-ch-ua": '"Not/A)Brand";v="8", "Chromium";v="126", "Google Chrome";v="126"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Linux"',
            "signcode": "",
        }

        self.login_json_data = {
            "ACC_NBR": "",
            "LOGIN_CODE": "",
            "MSG_TYPE": "SMS",
            "IS_COOKIE_PWD": "N",
            "VALIDATE_BOX_STATUS": False,
            "CUST_TYPE": "S",
        }

    def update_headers(self, headers: dict) -> None:
        self.headers.update(headers)
