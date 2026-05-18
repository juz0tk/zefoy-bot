

import os
import json
import string
import hashlib
import requests
from re import findall
from time import sleep, time as timee
from base64 import b64decode, b64encode
from random import choices, uniform
from typing import Any
from hashlib import md5
from requests import Session
from datetime import datetime
from urllib.parse import unquote
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BANNER = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡀⠀⠀⢀⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣤⣤⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⢿⣿⣿⣿⣿⣿⣿⡿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣀⣠⠀⣶⣤⣄⣉⣉⣉⣉⣠⣤⣶⠀⣄⣀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣶⣾⣿⣿⣿⣿⣦⣄⣉⣙⣛⣛⣛⣛⣋⣉⣠⣴⣿⣿⣿⣿⣷⣶⠀⠀⠀
⠀⠀⠀⠀⠈⠉⠉⠛⠛⠛⠻⠿⠿⠿⠿⠿⠿⠿⠿⠟⠛⠛⠛⠉⠉⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⣆⠀⠀⠀⢠⡄⠀⠀⠀⣰⣾⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢀⣠⣶⣾⣿⡆⠸⣿⣶⣶⣾⣿⣿⣷⣶⣶⣿⠇⢰⣿⣷⣶⣄⡀⠀⠀⠀
⠀⠀⠺⠿⣿⣿⣿⣿⣿⣄⠙⢿⣿⣿⣿⣿⣿⣿⡿⠋⣠⣿⣿⣿⣿⣿⠿⠗⠀⠀
⠀⠀⠀⠀⠀⠙⠻⣿⣿⣿⣷⡄⠈⠙⠛⠛⠋⠁⢠⣾⣿⣿⣿⠟⠋⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣀⣤⣬⣿⣿⣿⣇⠐⣿⣿⣿⣿⠂⣸⣿⣿⣿⣥⣤⣀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠘⠻⠿⠿⢿⣿⣿⣿⣧⠈⠿⠿⠁⣼⣿⣿⣿⡿⠿⠿⠟⠃⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⢿⠀⣶⣦⠀⡿⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
"""

DEFAULT_PASSWORD = "43fdda1192dde7f8ffff7161e13580d7"
KEY_BYTES = 32
IV_BYTES = 16

API_KEY = "K86199881188957"

TERM_SIZE = os.get_terminal_size().columns

def _print(thing: str = "?", content: str = "...", new_line: bool = True, input: bool = False) -> None | str:
    col = "\033[38;2;225;-;255m"
    first_part = f"[{thing}] | [{datetime.now().strftime('%H:%M:%S')}] {content}"
    new_part = ""

    counter = 0
    for char in first_part:
        new_part += col.replace("-", str(255 - counter * int(255 / len(first_part)))) + char
        counter += 1

    if input:
        return new_part

    if not new_line:
        print(f"{new_part}{' '*(TERM_SIZE - len(first_part))}\033[38;2;255;255;255m", end="\r")
    else:
        print(f"{new_part}{' '*(TERM_SIZE - len(first_part))}\033[38;2;255;255;255m")

def decode_response(response: str):
    return b64decode(unquote(response[::-1]).encode()).decode()

def evp_bytes_to_key(password: bytes, salt: bytes, key_size: int, iv_size: int) -> tuple[bytes, bytes]:
    derived = b""
    block = b""

    while len(derived) < key_size + iv_size:
        block = hashlib.md5(block + password + salt).digest()
        derived += block

    return derived[:key_size], derived[key_size : key_size + iv_size]

def encrypt_payload(
    plaintext: str | bytes,
    password: str = DEFAULT_PASSWORD,
    *,
    salt: bytes | None = None,
) -> dict[str, str]:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")

    if salt is None:
        salt = os.urandom(8)
    elif len(salt) != 8:
        raise ValueError("salt must be exactly 8 bytes")

    key, iv = evp_bytes_to_key(password.encode("utf-8"), salt, KEY_BYTES, IV_BYTES)
    ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))

    return {
        "ct": b64encode(ciphertext).decode("ascii"),
        "iv": iv.hex(),
        "s": salt.hex(),
    }

def decrypt_payload(
    encrypted: dict[str, str] | str,
    password: str = DEFAULT_PASSWORD,
) -> bytes:
    if isinstance(encrypted, str):
        encrypted = json.loads(encrypted)

    salt = bytes.fromhex(encrypted["s"])
    iv = bytes.fromhex(encrypted["iv"])
    ct = b64decode(encrypted["ct"])

    key, kdf_iv = evp_bytes_to_key(password.encode("utf-8"), salt, KEY_BYTES, IV_BYTES)
    if kdf_iv != iv:
        raise ValueError("IV does not match KDF output (corrupt or wrong password)")

    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)

def encrypt_json(data: Any, password: str = DEFAULT_PASSWORD, **kwargs: Any) -> dict[str, str]:
    return encrypt_payload(json.dumps(data, separators=(",", ":")), password, **kwargs)

def to_form_value(encrypted: dict[str, str]) -> str:
    return json.dumps(encrypted, separators=(",", ":"))

class OcrSpaceAPI:
    def __init__(self, api_key = "helloworld"):
        self.api_key = api_key
        self.endpoint = "https://api.ocr.space/parse/image"

    def ocr_image_file(self, file_path, language = "eng", overlay = True, engine = 2):
        with open(file_path, "rb") as f:
            response = requests.post(
                url = self.endpoint,
                files=  {
                    "file": (file_path, f)
                },
                data={
                    "language": language,
                    "isOverlayRequired": str(overlay).lower(),
                    "OCREngine": engine
                },
                headers={
                    "apikey": self.api_key
                }
            )

            data = response.json()

            if data.get("IsErroredOnProcessing"):
                raise Exception(f"OCR error: {data.get('ErrorMessage', 'Unknown error')}")

            parsed_results = data.get("ParsedResults", [])

            if parsed_results:
                return parsed_results[0].get("ParsedText", "")

            return ""
       
class Zefoy:
    def __init__(self) -> None:
        self.session = Session()
        self.api = OcrSpaceAPI(API_KEY)

        self.services = {}
        self.choice = 0
        self.video_url = ""

        self.keys = {
            "id": None
        }

    def generate_fingerprint(self):
        return {
            "deviceInfo": {
                "cpuCores": 4,
                "cpuLoad": "Skipped",
                "deviceMemoryGB": "Not Supported",
                "platform": "Win32",
                "maxTouchPoints": 10,
                "msMaxTouchPoints": "Not Supported",
                "gpu": {
                    "vendor": "Mozilla",
                    "renderer": "Mozilla"
                },
                "battery": "Not Supported",
                "stylusDetection": "Yes",
                "touchSupport": "No"
            },
            "browserInfo": {
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
                "timezone": "Atlantic/Reykjavik",
                "timezoneOffset": 0,
                "localeDateTime": "5/17/2026, 4:26:25 PM",
                "localUnixTime": 1779035185,
                "calendar": "gregory",
                "day": "numeric",
                "locale": "en-US",
                "month": "numeric",
                "numberingSystem": "latn",
                "year": "numeric",
                "appName": "Netscape",
                "appVersion": "5.0 (Windows)",
                "vendor": "",
                "language": "en-US",
                "languages": [
                    "en-US",
                    "en"
                ],
                "cookieEnabled": True,
                "onlineStatus": "Online",
                "javaEnabled": False,
                "doNotTrack": "unspecified",
                "referrerHeader": "None",
                "httpsConnection": "Yes",
                "historyLength": 5,
                "mimeTypes": 2,
                "plugins": 5,
                "webdriver": False,
                "pageVisibility": "visible",
                "isBot": "No",
                "featuresSupported": {
                    "geolocation": "No",
                    "serviceWorker": "No",
                    "localStorage": "Yes",
                    "sessionStorage": "Yes",
                    "indexedDB": "Yes",
                    "notifications": "Yes",
                    "notificationsFirebase": "default",
                    "clipboard": "Yes",
                    "pushAPI": "No",
                    "webRTC": "Yes",
                    "gamepadAPI": "Yes",
                    "speechSynthesis": "Yes",
                    "webGL": "Yes",
                    "vibrationAPI": "No",
                    "deviceMotion": "Yes",
                    "deviceOrientation": "Yes",
                    "wakeLock": "Yes",
                    "serial": "No",
                    "usb": "No",
                    "networkInformation": "No",
                    "screenCapture": "Yes",
                    "fullscreenAPI": "Yes",
                    "pictureInPicture": "No"
                }
            },
            "screenInfo": {
                "width": 688,
                "height": 919,
                "colorDepth": 24,
                "pixelDepth": 24,
                "devicePixelRatio": 2,
                "orientation": "portrait-primary",
                "screenOrientationAngle": 90,
                "availableWidth": 688,
                "availableHeight": 919,
                "screenLeft": 0,
                "screenTop": 0,
                "outerWidth": 688,
                "outerHeight": 919,
                "innerWidth": 688,
                "innerHeight": 919
            },
            "otherData": {
                "mouseAvailable": "Yes",
                "keyboardAvailable": "Yes",
                "bluetoothSupport": "No",
                "usbSupport": "No",
                "gamepadSupport": "Yes",
                "incognitoMode": "Not Supported"
            },
            "storageInfo": {
                "localStorage": 1,
                "sessionStorage": 0,
                "indexedDB": "Available",
                "cacheStorage": "Available",
                "storageEstimate": {
                    "quota": 10737418240,
                    "usage": 81947
                }
            }
        }

    def wait(self, time: int):
        for time_spent in range(time):
            sleep(1)
            _print("-", f"Remaining time: {(time - (time_spent + 1))}", new_line = False)
       
        print("")
        _print("+", f"Sending service")

    def retrieve_captcha_token(self):
        response = self.session.get(
            url = "https://zefoy.com/",
            headers = {
                "Host": "zefoy.com",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
            }
        ).text

        return findall(r'type="search" id="captchatoken" name="(.*?)"', response)[0]

    def get_captcha_url(self):
        response = self.session.get(
            url = f"https://zefoy.com/?getcapthca={int(timee())}",
            headers = {
                "Host": "zefoy.com",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
            }
        ).json()

        captcha_url_encoded: str = response[md5("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36".encode()).hexdigest()]
        captcha_url_decoded = b64decode(b64decode(captcha_url_encoded.encode())).decode().removeprefix("/")

        return f"https://zefoy.com/{captcha_url_decoded}"

    def retrieve_captcha(self, captcha_url):
        response = self.session.get(
            url = captcha_url,
            headers = {
                "Host": "zefoy.com",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
            }
        )

        with open("captcha_image.png", "wb") as f:
            f.write(response.content)

        return self.api.ocr_image_file("captcha_image.png")

    def post_captcha(self, captcha_token: str, captcha_value: str):
        encrypted = encrypt_json(self.generate_fingerprint())
        form_value = to_form_value(encrypted).replace(" ", "")

        response = self.session.post(
            url = "https://zefoy.com/",
            headers = {
                "Host": "zefoy.com",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                "Accept": "*/*",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": "https://zefoy.com",
                "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
            },
            data = {
                captcha_token: captcha_value,
                "captcha_encoded": form_value
            }
        ).text

        if "success" in response:
            return True

        return False

    def retrieve_services(self):
        response = self.session.get(
            url = "https://zefoy.com/",
            headers = {
                "Host": "zefoy.com",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
            }
        ).text

        all_services = findall(r'<h5 class="card-title mb-3"> (.*?)</h5>\n<form action="(.*?)">', response)
        working_services = findall(r'<button class="btn btn-primary rounded-0 t-(.*?)-button">', response)

        self.keys["id"] = findall(r'remove-spaces" name="(.*?)" placeholder', response)[0]

        counter = 0
        input_choices = {}

        for key, value in all_services:
            if key.lower() in working_services:
                counter += 1
                self.services[key.title()] = value
                input_choices[counter] = key

        for count, key in input_choices.items():
            _print(count, key)

        print("")
        self.choice = input_choices[int(input(_print("?", "Choose a service> ", input = True)))]
        self.video_url = input(_print("?", "Enter video link> ", input = True))
        print("")

    def search_service(self):
        rand_string = "".join(choices(string.digits + string.ascii_letters, k = 16))
        response = self.session.post(
            url = f"https://zefoy.com/{self.services[self.choice]}",
            headers = {
                "Host": "zefoy.com",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                "Accept": "*/*",
                "Content-Type": f"multipart/form-data; boundary=----WebKitFormBoundary{rand_string}",
                "Origin": "https://zefoy.com",
                "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
            },
            data = f"------WebKitFormBoundary{rand_string}\nContent-Disposition: form-data; name='{self.keys['id']}'\n\n{self.video_url}\n------WebKitFormBoundary{rand_string}--"
        ).text
        response = decode_response(response)

        if "Please wait" in response:
            try:
                self.wait(int(findall(r'var remainingTimelogin = (.*?);', response)[0]))
            except:
                self.wait(int(findall(r'var ltm=(.*?);', response)[0]))
        elif "fa fa-video-camera text-danger" in response:
            keys = {}

            for key, val in findall(r'name="(.*?)" value="(.*?)"', response):
                keys[key] = val

            sleep(uniform(1, 2))
            self.send(keys)

    def send(self, keys):
        rand_string = "".join(choices(string.digits + string.ascii_letters, k = 16))

        data = ""
        for k, v in keys.items():
            data += f"------WebKitFormBoundary{rand_string}\nContent-Disposition: form-data; name='{k}'\n\n{v}\n"
        data += f"------WebKitFormBoundary{rand_string}--"

        response = self.session.post(
            url = f"https://zefoy.com/{self.services[self.choice]}",
            headers = {
                "Host": "zefoy.com",
                "Connection": "keep-alive",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36",
                "Accept": "*/*",
                "Content-Type": f"multipart/form-data; boundary=----WebKitFormBoundary{rand_string}",
                "Origin": "https://zefoy.com",
                "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
            },
            data = data,
        ).text
        response = decode_response(response)

        if "Successfully" in response:
            _print("+", f"{self.choice} sent.")

            self.wait(int(findall(r'var ltm=(.*?);', response)[0]))

            sleep(uniform(1, 2))

    def task(self):
        captcha_token = self.retrieve_captcha_token()

        captcha_url = self.get_captcha_url()
        captcha_value = self.retrieve_captcha(captcha_url)

        if self.post_captcha(captcha_token, captcha_value):
            self.retrieve_services()

            while True:
                self.search_service()

if __name__ == "__main__":
    os.system("cls")
    os.system("title Zefoy")

    for line in BANNER.splitlines():
        print(line.center(TERM_SIZE))

    zef = Zefoy()

    while True:
        zef.task()