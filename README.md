# mojang-token
Lightweight python script for getting the Mojang API token with only email and password.

## Simple usage
```py
from mctoken import Auth

auth = Auth("email", "password")
token = auth.login()
```