import requests
import re

class Auth():
    def __init__(self, email: str, password: str) -> None:
        self.email = email
        self.password = password
        self.s = requests.Session()

    def oauth2(self):
        params = {
            "client_id": "000000004C12AE6F",
            "redirect_uri": "https://login.live.com/oauth20_desktop.srf",
            "scope": "service::user.auth.xboxlive.com::MBI_SSL",
            "display": "touch",
            "response_type": "token",
            "locale": "en",
        }

        resp = self.s.get("https://login.live.com/oauth20_authorize.srf", params=params)
        # Parses the values via regex since the HTML can't be parsed
        value = re.search(r'value="(.+?)"', resp.text)[0].replace('value="', "")[:-1]
        url = re.search(r"urlPost:'(.+?)'", resp.text)[0].replace("urlPost:'", "")[:-1]

        return [value, url]

    def microsoft(self, value, url):
        headers = {"Content-Type": "application/x-www-form-urlencoded"
        }

        payload = {
                    "login": self.email,
                    "loginfmt": self.email,
                    "passwd": self.password,
                    "PPFT": value,
                }

        resp = self.s.post(url, data=payload, headers=headers, allow_redirects=True)
        if "access_token" not in resp.url:
            print("Login fail")
            print(resp.url)
            if b"Sign in to" in resp.content:
                print("Sign in to")
            if b"Help us" in resp.content:
                print("Help us")

        raw_login_data = resp.url.split("#")[1]
        login_data = dict(item.split("=") for item in raw_login_data.split("&")) # create a dictionary of the parameters
        login_data["access_token"] = requests.utils.unquote(login_data["access_token"]) # URL decode the access token
        login_data["refresh_token"] = requests.utils.unquote(login_data["refresh_token"]) # URL decode the refresh token
        return login_data

    def xboxlive(self, access_token):
        json_data = {
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": access_token,
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        }

        resp = self.s.post("https://user.auth.xboxlive.com/user/authenticate", json=json_data)

        xbl_token = resp.json()["Token"]
        user_hash = resp.json()["DisplayClaims"]["xui"][0]["uhs"]
        return [xbl_token, user_hash]

    def xsts(self, xbl_token):
        payload = {
            "Properties": {"SandboxId": "RETAIL", "UserTokens": [xbl_token]},
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT",
        }

        resp = self.s.post("https://xsts.auth.xboxlive.com/xsts/authorize", json=payload)

        return resp.json()["Token"]

    def minecraft(self, user_hash, xsts_token):
        payload = {
            "identityToken": f"XBL3.0 x={user_hash};{xsts_token}",
            "ensureLegacyEnabled": True,
        }

        resp = self.s.post("https://api.minecraftservices.com/authentication/login_with_xbox", json=payload)

        return resp.json()

    def login(self):
        value, url = self.oauth2()
        login_data = self.microsoft(value, url)
        access_token = login_data["access_token"]
        xbl_token, user_hash = self.xboxlive(access_token)
        xsts_token = self.xsts(xbl_token)
        data = self.minecraft(user_hash, xsts_token)

        return data["access_token"]