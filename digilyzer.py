#!/usr/bin/env python3

"""
Digilyzer - een onofficiele, open-source DigiD app

WAARSCHUWING: Dit is experimentele software. Ondeskundig gebruik kan
    de beveiliging van uw DigiD in gevaar brengen. Lees eerst README.txt.

Gebruik:
    python3 digilyzer.py {status|checkversion|activate|complete|authenticate}
                         [--verbose]

Functies:
    status          Activatiestatus weergeven (maakt geen contact met server)
    checkversion    Check versie en compatibiliteit met de server
    activate        Activatie starten
    complete        Activatie afronden na ontvangst van brief met activatiecode
    authenticate    Inloggen op een website via DigiD

Opties:
    --verbose       Print extra details over de voortgang
"""


import sys
import argparse
import base64
import enum
import getpass
import json
import os
import os.path
import pathlib
import re
import secrets
import ssl
import time
import uuid
import urllib3
import PIL.Image
import cryptography.fernet
import cryptography.hazmat.primitives.asymmetric.ec
import cryptography.hazmat.primitives.ciphers
import cryptography.hazmat.primitives.ciphers.algorithms
import cryptography.hazmat.primitives.ciphers.modes
import cryptography.hazmat.primitives.hashes
import cryptography.hazmat.primitives.kdf.pbkdf2
import cryptography.hazmat.primitives.padding
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.backends

import qrdecode


opt_verbose = False


def log(s):
    if opt_verbose:
        print("..", s)


class ApiError(Exception):
    def __init__(self, error_message, status=""):
        super().__init__(error_message)
        self.status = status


class ApplicationError(Exception):
    pass


if sys.platform.startswith("linux"):
    # Module PIL.ImageGrab is not supported on Linux.
    # Use GTK to get screenshot / clipboard.

    def get_screenshot():
        """Take a screenshot and return it as a PIL image."""
        import io
        import gi
        gi.require_version("Gdk", "3.0")
        from gi.repository import Gdk
        win = Gdk.get_default_root_window()
        w = win.get_width()
        h = win.get_height()
        pixbuf = Gdk.pixbuf_get_from_window(win, 0, 0, w, h)
        if not pixbuf:
            raise ApplicationError("Kan geen screenshot maken")
        (ok, pngdata) = pixbuf.save_to_bufferv("png", [], [])
        if not ok:
            raise ApplicationError("Kan de screenshot niet converteren naar PNG")
        return PIL.Image.open(io.BytesIO(pngdata))

    def get_clipboard_image():
        """Get an image from the clipboard."""
        import io
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gdk
        from gi.repository import Gtk
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        pixbuf = clipboard.wait_for_image()
        if not pixbuf:
            raise ApplicationError("Geen afbeelding gevonden op het clipboard")
        (ok, pngdata) = pixbuf.save_to_bufferv("png", [], [])
        if not ok:
            raise ApplicationError("Kan de afbeelding niet converteren naar PNG")
        return PIL.Image.open(io.BytesIO(pngdata))

else:

    def get_screenshot():
        """Take a screenshot and return it as a PIL image."""
        import PIL.ImageGrab
        from ctypes import windll
        user32 = windll.user32
        user32.SetProcessDPIAware()  # necessary to ensure full screen grab
        return PIL.ImageGrab.grab()

    def get_clipboard_image():
        """Get an image from the clipboard."""
        import PIL.ImageGrab
        return PIL.ImageGrab.grabclipboard()


class DigidUI:

    def msg(self, s):
        print(s)

    def _prompt_string(self, message):
        print(message, end="")
        sys.stdout.flush()
        val = sys.stdin.readline()
        return val.rstrip("\r\n")

    def prompt_settings_passphrase(self):
        return getpass.getpass("Digilyzer wachtwoord: ")

    def prompt_username(self):
        return self._prompt_string("DigiD gebruikersnaam: ")

    def prompt_password(self):
        return getpass.getpass("DigiD wachtwoord: ")

    def prompt_pincode(self):
        return getpass.getpass("Pincode: ")

    def prompt_activationcode(self):
        return self._prompt_string("Activatiecode: ")

    def show_koppelcode(self, koppelcode):
        print("Koppelcode: {}".format(koppelcode))

    def get_qrcode(self):
        print("Op de website verschijnt een QR code.")
        while True:
            print()
            print("Kies een methode om de QR code te laden:")
            print("  1. Via het clipboard")
            print("  2. Door middel van een screenshot")
            print("  3. Afbeelding laden uit een bestand")
            while True:
                s = self._prompt_string("Kies 1, 2 of 3: ")
                try:
                    v = int(s.strip())
                    if v in (1, 2, 3):
                        break
                except ValueError:
                    pass
                print("Ongeldige keuze")
            print()
            try:
                if v == 1:
                    print("Plaats een screenshot van de QR code op het clipboard,")
                    print("bijvoorbeeld door in de browser op Alt-PrtScr te drukken.")
                    s = self._prompt_string("Druk daarna op Enter ... ")
                    print()
                    img = get_clipboard_image()
                    if img is None:
                        print("FOUT: Geen afbeelding gevonden op het clipboard")
                        continue
                elif v == 2:
                    print("Zorg dat de QR code zichtbaar is op het scherm.")
                    s = self._prompt_string("Druk dan op Enter om een screenshot te maken ... ")
                    print()
                    img = get_screenshot()
                    if img is None:
                        print("FOUT: Kan geen screenshot maken")
                        continue
                elif v == 3:
                    print("Maak een screenshot van de QR code en bewaar de afbeelding")
                    print("als een bestand. Voer de volledige bestandsnaam in.")
                    s = self._prompt_string("Bestandsnaam: ")
                    print()
                    img = PIL.Image.open(s)
                print("Afbeelding: {}x{} pixels".format(img.width, img.height))
            except Exception as exc:
                print("FOUT:", type(exc).__name__ + ":", exc)
                continue
            try:
                qrdata = qrdecode.decode_qrcode(img)
            except Exception as exc:
                print("FOUT: Geen QR code gevonden in afbeelding")
                print(type(exc).__name__ + ":", exc)
                continue
            return qrdata.decode("ascii")

    def confirm_activation(self):
        while True:
            val = self._prompt_string("Activatie starten (j/n)? ")
            val = val.lower()
            if val == "j":
                return True
            if val == "n":
                return False


class HttpClient:

    # Host name van de DigiD backend server.
    DIGID_HOST = "digid.nl"

    # SHA-256 fingerprint van het TLS certificaat van de DigiD backend server.
    DIGID_SSL_FINGERPRINT = (
        "5b:c0:2b:e7:e0:77:83:be:aa:b0:5d:9c:b0:74:09:79"
        + ":6d:5b:ec:ae:11:b1:7b:8e:f6:0e:f1:1c:e6:5d:ba:50")

    def __init__(self):
        self._fixed_headers = {
            "API-Version":  "2",
            "App-Version":  "5.14.0",
            "OS-Type":      "Android",
            "OS-Version":   "7.1.1",
            "Release-Type": "Productie",
            "Accept":       "application/json",
            "User-Agent":   "okhttp/3.2.0"
        }
        self.persistcookie = None
        ca_certs = os.path.join(os.path.dirname(__file__),
                                "Staat_der_Nederlanden_EV_Root_CA.pem")
        self._pool = urllib3.HTTPSConnectionPool(
            host=self.DIGID_HOST,
            maxsize=1,
            ca_certs=ca_certs,
            assert_fingerprint=self.DIGID_SSL_FINGERPRINT)

    def get(self, path):
        """Stuur een HTTPS GET opdracht naar de DigiD server.

        Parameters:
            path:   Absolute pad component in de URL.

        Resultaat:
            Dict van key/value paren uit het antwoord van de server.
        """
        url = "https://" + self.DIGID_HOST + path
        headers = {}
        headers.update(self._fixed_headers)
        if self.persistcookie:
            headers["Cookie"] = "_persist=" + self.persistcookie
        log("HTTP GET " + url)
        resp = self._pool.request("GET", url, headers=headers, timeout=10.0)
        return self._decode_response(resp)

    def post(self, path, data):
        """Stuur een HTTPS POST opdracht naar de DigiD server.

        Parameters:
            path:   Absolute pad component in de URL.
            data:   Dict van key/value paren om naar de server te sturen.

        Resultaat:
            Dict van key/value paren uit het antwoord van de server.
        """
        body = json.dumps(data).encode("ascii")
        url = "https://" + self.DIGID_HOST + path
        headers = {"Content-Type": "application/json"}
        headers.update(self._fixed_headers)
        if self.persistcookie:
            headers["Cookie"] = "_persist=" + self.persistcookie
        log("HTTP POST " + url)
        resp = self._pool.request("POST",
                                  url,
                                  body=body,
                                  headers=headers,
                                  timeout=10.0)
        return self._decode_response(resp)

    def _handle_cookies(self, cookies):
        """Verwerk een "Set-Cookie" header uit een HTTP antwoord.

        Alleen de "_persist" cookie wordt herkend. De inhoud hiervan
        wordt bewaard en bij volgende HTTP opdrachten teruggestuurd naar
        de DigiD server.
        """
        for cookie in cookies:
            if cookie.startswith("_persist="):
                v = cookie[9:]
                p = v.find(";")
                if p >= 0:
                    v = v[:p]
                p = v.find(" ")
                if p >= 0:
                    v = v[:p]
                if len(v) > 1 and v[0] == '"' and v[-1] == '"':
                    v = v[1:-1]
                self.persistcookie = v

    def _decode_response(self, resp):
        """Verwerk het antwoord op een HTTP opdracht.

        Behandel het antwoord als een JSON structuur.
        Geef als resultaat een dict van key/value paren uit de JSON structuur.

        Geef een ApiError exception als de HTTP opdracht faalt, of
        als de server een "status" veld ongelijk aan "ok" teruggeeft.
        """
        log("HTTP status: {} {}".format(resp.status, resp.reason))
        if resp.status < 200 or resp.status > 299:
            errmsg = "HTTP status {} ({})".format(resp.status, resp.reason)
            status = "http_{}".format(resp.status)
            raise ApiError(errmsg, status)
        log("HTTP headers: " + str(resp.headers))
        log("HTTP data: {!r}".format(resp.data))
        cookies = resp.headers.getlist("Set-Cookie")
        self._handle_cookies(cookies)
        val = json.loads(resp.data.decode("ascii"))
        if not isinstance(val, dict):
            raise ApiError("Bad JSON message")
        status = str(val.get("status", "")).lower()
        error = str(val.get("error", ""))
        if status and (status != "ok"):
            errmsg = "Got API status {!r} ({})".format(status, error)
            raise ApiError(errmsg, status)
        return val


class LoginLevel(enum.IntEnum):
    UNKNOWN = 0
    BASIS = 10
    MIDDEN = 20
    SUBSTANTIEEL = 25
    HOOG = 30


class DigidSettings:
    """Instellingen die worden opgeslagen tussen Digilyzer sessies.

    Deze gegevens worden aangemaakt tijdens het activatie proces,
    en zijn in volgende Digilyzer sessies weer nodig om in te loggen.

    Deze gegevens worden opgeslagen in het bestand "digilyzer.settings".
    """

    _FIELDS = (
        "activation_status",    # Status van activatieproces.
        "app_id",               # ID van deze client, gekozen door server.
        "instance_id",          # ID van deze client, gekozen door app.
        "symmetric_key",        # Encryptiesleutel voor de pincode.
        "mask_code",            # Willekeurige code voor maskeren van pincode.
        "public_key",           # Publieke ECDSA sleutel.
        "private_key",          # Geheime ECDSA sleutel.
        "login_level")          # Login niveau (integer).

    def __init__(self):
        self.activation_status = "not_activated"
        self.app_id = ""
        self.instance_id = ""
        self.symmetric_key = ""
        self.mask_code = ""
        self.login_level = 0
        self.public_key = ""
        self.private_key = ""

    def from_dict(self, d):
        for field in self._FIELDS:
            setattr(self, field, d.get(field))

    def as_dict(self):
        return dict((field, getattr(self, field)) for field in self._FIELDS)


class DigidClient:

    DEVICE_NAME = "Samsung Galaxy S6"

    def __init__(self):
        self.app_session_id = None
        self._http = HttpClient()

    def set_session_id(self, session_id):
        self.app_session_id = session_id

    def set_persistcookie(self, persistcookie):
        self._http.persistcookie = persistcookie

    def check_version(self):
        # Returns:
        #   action: str
        #   update_url: str
        resp = self._http.get("/apps/version")
        return resp

    def basic_authenticate(self, username, password):
        # Returns:
        #   app_session_id: str
        #   activation_method: str
        #   app_authenticator_pending: bool
        #   max_amount: int
        data = {
            "username": username,
            "password": password,
            "device_name": self.DEVICE_NAME
        }
        resp = self._http.post("/apps/auth", data)
        app_session_id = resp.get("app_session_id")
        if not app_session_id:
            raise ApiError("BasicAuthenticate did not return 'app_session_id'")
        self.app_session_id = app_session_id
        return resp

    def basic_authentication_session(self, settings, smscode):
        # Returns:
        #   user_app_id: str
        #   koppelcode: str
        #   max_amount: int
        data = {
            "app_session_id": self.app_session_id,
            "instance_id": settings.instance_id,
            "device_name": self.DEVICE_NAME,
            "smscode": smscode
        }
        resp = self._http.post("/apps/session", data)
        return resp

    def enrollment_challenge(self, settings):
        # Returns:
        #   challenge: str
        data = {
            "app_session_id": self.app_session_id,
            "user_app_id": settings.app_id,
            "app_public_key": settings.public_key
        }
        resp = self._http.post("/apps/challenge", data)
        return resp

    def complete_challenge(self, settings, signed_challenge):
        # Returns:
        #   symmetric_key: str
        #   iv: str
        data = {
            "app_session_id": self.app_session_id,
            "signed_challenge": signed_challenge,
            "app_public_key": settings.public_key,
            "hardware_support": False,
            "nfc_support": False
        }
        resp = self._http.post("/apps/challenge_response", data)
        status = resp.get("status")
        return resp

    def complete_activation(self, settings, masked_pincode):
        # Returns:
        #   authentication_level: int
        data = {
            "app_session_id": self.app_session_id,
            "masked_pincode": masked_pincode,
            "user_app_id": settings.app_id
        }
        resp = self._http.post("/apps/pincode", data)
        return resp

    def init_letter_activation(self):
        data = {"app_session_id": self.app_session_id}
        resp = self._http.post("/apps/letter", data)

    def poll_letter_activation(self):
        data = {"app_session_id": self.app_session_id}
        resp = self._http.post("/apps/letter_poll", data)

    def create_activation_code_session(self, settings):
        # Returns:
        #   app_session_id: str
        data = {"app_session_id": None,
                "user_app_id": settings.app_id,
                "re_request_letter": False}
        resp = self._http.post("/apps/activationcode_session", data)
        app_session_id = resp.get("app_session_id")
        if not app_session_id:
            raise ApiError("CreateActivationCodeSession did not return 'app_session_id'")
        self.app_session_id = app_session_id

    def complete_letter_activation(self, activationcode):
        data = {
            "app_session_id": self.app_session_id,
            "activationcode": activationcode
        }
        resp = self._http.post("/apps/activationcode", data)

    def send_sms(self):
        # Returns:
        #   phonenumber: str
        data = {"app_session_id": self.app_session_id}
        resp = self._http.post("/apps/sms", data)
        return resp

    def authenticate_challenge(self, settings):
        # Returns:
        #   challenge: str
        #   iv: str
        #   webservice: str
        #   action: str
        #   return_url: str
        #   authentication_level: int (formatted as string)
        data = {
            "app_session_id": self.app_session_id,
            "user_app_id": settings.app_id,
            "instance_id": settings.instance_id
        }
        resp = self._http.post("/apps/challenge", data)
        return resp

    def authenticate(self, settings, signed_challenge, masked_pincode):
        # Returns:
        #   authentication_level: int
        data = {
            "app_session_id": self.app_session_id,
            "user_app_id": settings.app_id,
            "app_public_key": settings.public_key,
            "signed_challenge": signed_challenge,
            "masked_pincode": masked_pincode,
            "upgrade_app": False
        }
        resp = self._http.post("/apps/authenticate", data)
        return resp


def bytes_to_hex(data):
    return "".join("{:02x}".format(b) for b in data)


def hex_to_bytes(s):
    n = len(s)
    if n % 2 != 0:
        raise ValueError("Expecting even-length hexadecimal string")
    values = [int(s[i:i+2], 16) for i in range(0, n, 2)]
    return bytes(values)


def make_ec_keypair():
    """Maak een publiek/geheim paar sleutels op de elliptic curve SECP256R1.

    Geef als resultaat het tuple (public_key, private_key).
    Beide sleutels worden in base16 representatie opgeleverd.
    """
    priv_key = cryptography.hazmat.primitives.asymmetric.ec.generate_private_key(
        cryptography.hazmat.primitives.asymmetric.ec.SECP256R1,
        cryptography.hazmat.backends.default_backend())
    priv_key_bytes = priv_key.private_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.DER,
        cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
        cryptography.hazmat.primitives.serialization.NoEncryption())
    priv_key_str = bytes_to_hex(priv_key_bytes)
    pub_key = priv_key.public_key()
    pub_key_bytes = pub_key.public_bytes(
        cryptography.hazmat.primitives.serialization.Encoding.X962,
        cryptography.hazmat.primitives.serialization.PublicFormat.UncompressedPoint)
    pub_key_str = bytes_to_hex(pub_key_bytes)
    return (pub_key_str, priv_key_str)


def ec_sign(private_key, data):
    """Onderteken een bericht met ECDSA-SHA256.

    Parameters:
        private_key: Geheime sleutel in het formaat van make_ec_keypair().
        data:        String om te ondertekenen.

    Resultaat:
        Digitale handtekening als de base16 representatie van de ECDSA
        handtekening in DER codering.
    """
    priv_key_bytes = hex_to_bytes(private_key)
    data_bytes = data.encode("utf-8")
    priv_key = cryptography.hazmat.primitives.serialization.load_der_private_key(
        priv_key_bytes,
        password=None,
        backend=cryptography.hazmat.backends.default_backend())
    algorithm = cryptography.hazmat.primitives.asymmetric.ec.ECDSA(
        cryptography.hazmat.primitives.hashes.SHA256())
    signed_data = priv_key.sign(data_bytes, algorithm)
    return bytes_to_hex(signed_data)


def valid_pincode(pincode):
    return (len(pincode) == 5) and re.match(r"^[0-9]{5}$", pincode)


def make_pincode_mask():
    """Genereer een willekeurige code van 5 cijfers."""
    return "{:05d}".format(secrets.randbelow(100000))


def mask_pincode(mask, pincode):
    """Maskeer de pincode door er een masker code bij op te tellen."""
    mask_digits = [int(c) for c in mask]
    pin_digits = [int(c) for c in pincode]
    assert len(mask_digits) == 5
    assert len(pin_digits) == 5
    masked_digits = [(m + p) % 10
                     for (m, p) in zip(mask_digits, pin_digits)]
    masked_code = "".join(str(c) for c in masked_digits)
    return masked_code


def encrypt_pincode(symmetric_key, iv, data):
    """Versleutel de gemaskeerde pincode met AES-256-CBC.

    Parameters:
        symmetric_key:  Base16 representatie van de AES-256 sleutel.
        iv:             Base16 representatie van de IV.
        data:           Gemaskeerde pincode om te versleutelen.

    Resultaat:
        Versleutelde data in base16 representatie.
    """
    data_bytes = data.encode("utf-8")
    key_bytes = hex_to_bytes(symmetric_key)
    iv_bytes = hex_to_bytes(iv)
    if len(key_bytes) != 32:
        raise ValueError("Unsupported symmetric key length")
    if len(iv_bytes) != 16:
        raise ValueError("Unsupported IV length")
    cipher = cryptography.hazmat.primitives.ciphers.Cipher(
        cryptography.hazmat.primitives.ciphers.algorithms.AES(key_bytes),
        cryptography.hazmat.primitives.ciphers.modes.CBC(iv_bytes),
        backend=cryptography.hazmat.backends.default_backend())
    ctx = cipher.encryptor()
    padder = cryptography.hazmat.primitives.padding.PKCS7(128).padder()
    padded_bytes = padder.update(data_bytes) + padder.finalize()
    encrypted_bytes = ctx.update(padded_bytes) + ctx.finalize()
    return bytes_to_hex(encrypted_bytes)


def make_koppelcode():
    """Genereer een willekeurige "koppelcode" van 4 letters."""
    code_len = 4
    allowed_chars = "BCDFGHJLMNPQRSTVWXZ"
    code_chars = []
    for i in range(code_len):
        r = secrets.randbelow(len(allowed_chars))
        code_chars.append(allowed_chars[r])
    return "".join(code_chars)


class DigidApp:

    def __init__(self):
        self.settings_file = os.path.join(pathlib.Path.home(),
                                          "digilyzer.settings")
        self.settings = None
        self._cli = DigidClient()
        self._ui = DigidUI()
        self._settings_salt = None
        self._settings_key = None

    def _derive_settings_key(self, salt, passphrase):
        kdf = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
            algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=4096,
            backend=cryptography.hazmat.backends.default_backend())
        key = kdf.derive(passphrase.encode("utf-8"))
        self._settings_salt = salt
        self._settings_key = base64.urlsafe_b64encode(key)

    def _prompt_new_passphrase(self):
        msg = self._ui.msg
        msg("Tijdens activatie worden geheime sleutels en codes aangemaakt.")
        msg("Deze instellingen worden opgeslagen in het bestand digilyzer.settings.")
        msg("U kunt de instellingen beveiligen met een wachtwoord.")
        msg("")
        msg("Kies een wachtwoord om de instellingen te beveiligen.")
        msg("Het gaat hier NIET om uw wachtwoord voor de DigiD website.")
        msg("Het wachtwoord moet opnieuw worden ingevoerd bij elk gebruik van")
        msg("deze software. Als u een leeg wachtwoord invoert (Enter), worden")
        msg("de instellingen onbeveiligd opgeslagen.")
        msg("")
        while True:
            passphrase = self._ui.prompt_settings_passphrase()
            if passphrase.strip() == "":
                msg("")
                msg("Instellingen worden onbeveiligd opgeslagen.")
                self._settings_salt = None
                self._settings_key = None
                return
            msg("Voer nogmaals hetzelfde wachtwoord in ter controle.")
            passphrase2 = self._ui.prompt_settings_passphrase()
            if passphrase == passphrase2:
                msg("")
                salt = secrets.token_bytes(16)
                self._derive_settings_key(salt, passphrase)
                return
            msg("Niet hetzelfde wachtwoord. Probeer opnieuw.")

    def _decrypt_settings(self, raw_data):
        msg = self._ui.msg
        tag = b"%digilyzer1%"
        if raw_data.startswith(tag):
            p = raw_data.find(b"%", len(tag))
            if p < 0:
                raise ApplicationError("Ongeldig bestandsformaat voor instellingen AA")
            salt = base64.urlsafe_b64decode(raw_data[len(tag):p])
            cipher_data = raw_data[p+1:]
            if len(salt) != 16:
                raise ApplicationError("Ongeldig bestandsformaat voor instellingen BB")
            if salt == self._settings_salt:
                # Try stored encryption key.
                try:
                    plain_data = fernet.decrypt(cipher_data)
                    return plain_data
                except cryptography.fernet.InvalidToken:
                    pass
            msg("De instellingen zijn beveiligd met een wachtwoord.")
            msg("Voer het wachtwoord in om de instellingen de ontcijferen.")
            msg("Het gaat hier NIET om uw wachtwoord voor de DigiD website.")
            while True:
                msg("")
                passphrase = self._ui.prompt_settings_passphrase()
                self._derive_settings_key(salt, passphrase)
                fernet = cryptography.fernet.Fernet(self._settings_key)
                try:
                    plain_data = fernet.decrypt(cipher_data)
                    return plain_data
                except cryptography.fernet.InvalidToken:
                    msg("Onjuist wachtwoord.")
        else:
            # plain text JSON
            self._settings_salt = None
            self._settings_key = None
            return raw_data

    def _encrypt_settings(self, plain_data):
        if self._settings_key:
            fernet = cryptography.fernet.Fernet(self._settings_key)
            cipher_data = fernet.encrypt(plain_data)
            raw_data = (b"%digilyzer1%"
                        + base64.urlsafe_b64encode(self._settings_salt)
                        + b"%"
                        + cipher_data)
        else:
            raw_data = plain_data
        return raw_data

    def load_settings(self):
        msg = self._ui.msg
        try:
            with open(self.settings_file, "rb") as f:
                msg("Instellingen worden gelezen uit {}".format(self.settings_file))
                raw_data = f.read()
        except FileNotFoundError:
            msg("Geen instellingen gevonden in {}".format(self.settings_file))
            self.settings = None
            return False
        plain_data = self._decrypt_settings(raw_data)
        json_data = json.loads(plain_data)
        self.settings = DigidSettings()
        self.settings.from_dict(json_data)
        return True

    def save_settings(self):
        msg = self._ui.msg
        msg("Instellingen worden opgeslagen in {}".format(self.settings_file))
        json_data = self.settings.as_dict()
        plain_data = json.dumps(json_data, indent=4).encode("utf-8")
        raw_data = self._encrypt_settings(plain_data)
        with open(os.open(self.settings_file,
                          os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                          0o600), "wb") as f:
            f.write(raw_data)

    def check_version(self):
        """Stuur een CheckVersion opdracht naar de DigiD server."""
        msg = self._ui.msg
        msg("DigiD server query: CheckVersion")
        resp = self._cli.check_version()
        action = resp.get("action", "")
        if action == "active":
            msg("CheckVersion - OK")
        else:
            msg("CheckVersion niet OK - action = {!r}".format(action))
            raise ApplicationError("Onverwacht resultaat van CheckVersion")

    def status(self):
        """Lees de Digilyzer instellingen en rapporteer de activatie status."""

        msg = self._ui.msg
        self.load_settings()

        msg("")
        if self.settings is None:
            msg("Status: geen instellingen gevonden")
        else:
            msg("Status:      {}".format(self.settings.activation_status))
            msg("instance_id: {}".format(self.settings.instance_id))
            msg("app_id:      {}".format(self.settings.app_id))
            try:
                login_level_str = LoginLevel(self.settings.login_level).name
            except ValueError:
                login_level_str = "???"
            msg("login_level: {} ({})"
                .format(self.settings.login_level, login_level_str))

    def activate(self):
        """Start het activatie proces."""

        msg = self._ui.msg
        self.check_version()
        self.load_settings()

        if self.settings is None:
            self.settings = DigidSettings()
            msg("")
            self._prompt_new_passphrase()

        if self.settings.activation_status != "not_activated":
            msg("Onverwachte actievatiestatus in instellingen: {}"
                .format(self.settings.activation_status))
            raise ApplicationError(
                "Kan niet starten met activatie - activatie was al gestart")

        # Genereer een willekeurige UUID om te gebruiken als "instance_id".
        self.settings.instance_id = str(uuid.uuid4())
        log("nieuw instance_id = {}".format(self.settings.instance_id))

        # Genereer een ECDSA publiek/geheim paar sleutels.
        (self.settings.public_key,
         self.settings.private_key) = make_ec_keypair()
        self.settings.mask_code = make_pincode_mask()
        self.save_settings()

        msg("")
        msg("Om activatie te starten zijn uw DigiD gebruikersnaam en")
        msg("wachtwoord nodig. Dit zijn dezelfde gegevens die u ook gebruikt")
        msg("om in te loggen op digid.nl.")
        msg("")

        username = self._ui.prompt_username()
        if not username:
            raise ApplicationError(
                "Ongeldige gebruikersnaam - activatie afgebroken")

        password = self._ui.prompt_password()
        if not password:
            raise ApplicationError(
                "Ongeldig wachtwoord - activatie afgebroken")

        msg("")
        msg("Kies een pincode van 5 cijfers.")
        msg("Deze pincode moet opnieuw worden ingevoerd bij" +
            " elk gebruik van deze software.")

        while True:
            pincode = self._ui.prompt_pincode()
            if not valid_pincode(pincode):
                msg("Ongeldige pincode, probeer opnieuw.")
            msg("Voer nogmaals dezelfde pincode in ter controle.")
            pincode2 = self._ui.prompt_pincode()
            if pincode2 == pincode:
                break
            msg("Pincodes zijn niet hetzelfde, probeer opnieuw.")

        msg("")
        msg("DigiD server query: BasicAuthenticate")
        resp = self._cli.basic_authenticate(username, password)
        activation_method = resp.get("activation_method")
        if resp.get("app_authenticator_pending"):
            msg("WAARSCHUWING: DigiD server zegt activatie is al gestart.")
        if activation_method == "standalone":
            msg("Activatie methode: activatiecode via SMS")
        elif activation_method == "letter":
            msg("Activatie methode: activatiecode via brief")
        else:
            raise ApplicationError(
                "Onbekende activatie methode {!r}".format(activation_method))

        msg("")
        if not self._ui.confirm_activation():
            return

        if activation_method == "standalone":
            self._activate_sms()
        elif activation_method == "letter":
            self._activate_letter()

        msg("DigiD server query: EnrollmentChallenge")
        resp = self._cli.enrollment_challenge(self.settings)
        challenge = resp.get("challenge")
        if not challenge:
            raise ApiError("EnrollmentChallenge did not return 'challenge'")

        signed_challenge = ec_sign(self.settings.private_key, challenge)
        msg("DigiD server query: CompleteChallenge")
        resp = self._cli.complete_challenge(self.settings, signed_challenge)
        self.settings.symmetric_key = resp.get("symmetric_key")
        iv = resp.get("iv")
        if not self.settings.symmetric_key:
            raise ApiError("CompleteChallenge did not return 'symmetric_key'")
        if not iv:
            raise ApiError("CompleteChallenge did not return 'iv'")

        masked_pincode = mask_pincode(self.settings.mask_code, pincode)
        masked_pincode = encrypt_pincode(self.settings.symmetric_key,
                                         iv,
                                         masked_pincode)

        msg("DigiD server query: CompleteActivation")
        authentication_level = None
        try:
            resp = self._cli.complete_activation(self.settings, masked_pincode)
            authentication_level = resp.get("authentication_level")
        except ApiError as exc:
            if (activation_method != "letter") or (exc.status != "pending"):
                raise

        msg("")
        if activation_method == "standalone":
            if not isinstance(authentication_level, int):
                raise ApiError(
                    "CompleteActivation did not return 'authentication_level'")
            msg("Activatie geslaagd (login_level={})."
                .format(authentication_level))
            msg("De 'authenticate' functie is nu beschikbaar.")
            self.settings.activation_status = "activated"
            self.settings.login_level = authentication_level
        elif activation_method == "letter":
            msg("Brief met activatiecode aangevraagd.")
            msg("Gebruik de 'complete' functie na ontvangst van de brief.")
            self.settings.activation_status = "pending"
        self.save_settings()

    def _activate_sms(self):
        """Ontvang activatiecode via SMS en bevestig deze naar de server."""

        msg = self._ui.msg
        msg("")
        msg("DigiD server query: SendSMS")
        resp = self._cli.send_sms()
        phonenumber = resp.get("phonenumber")

        msg("")
        msg("U ontvangt een activatiecode via SMS op telefoonnr {}."
            .format(phonenumber))
        msg("Voer deze code in (6 tekens).")

        while True:
            smscode = self._ui.prompt_activationcode()
            smscode = smscode.strip()
            if len(smscode) == 6:
                break
            msg("Ongeldige activatiecode, probeer opnieuw.")
        msg("")

        msg("DigiD server query: BasicAuthenticationSession")
        resp = self._cli.basic_authentication_session(self.settings, smscode)
        self.settings.app_id = resp.get("user_app_id")
        if not self.settings.app_id:
            raise ApiError("BasicAuthenticationSession did not return 'user_app_id'")

    def _activate_letter(self):
        """Vraag de server om een activatiecode per brief."""

        msg = self._ui.msg
        msg("DigiD server query: BasicAuthenticationSession")
        resp = self._cli.basic_authentication_session(self.settings, None)
        self.settings.app_id = resp.get("user_app_id")
        if not self.settings.app_id:
            raise ApiError("BasicAuthenticationSession did not return 'user_app_id'")

        msg("DigiD server query: InitLetterActivation")
        self._cli.init_letter_activation()

        while True:
            time.sleep(2)
            msg("DigiD server query: PollLetterActivation")
            try:
                self._cli.poll_letter_activation()
            except ApiError as exc:
                if exc.status != "pending":
                    raise
                continue
            break

    def complete(self):
        """Activatie afronden na ontvangst van de brief met activatiecode."""

        msg = self._ui.msg
        self.check_version()
        self.load_settings()

        if self.settings is None:
            raise ApplicationError(
                "Kan activatie niet afronden - geen instellingen gevonden")
        if self.settings.activation_status != "pending":
            msg("Onverwachte actievatiestatus in instellingen: {}"
                .format(self.settings.activation_status))
            if self.settings.activation_status == "activated":
                raise ApplicationError(
                    "Kan activatie niet afronden - app is al geactiveerd")
            else:
                raise ApplicationError(
                    "Kan activatie niet afronden - activatie nog niet gestart")

        msg("")
        msg("U heeft een brief ontvangen met een activatiecode (9 tekens).")
        msg("Voer deze code in.")
        activationcode = self._ui.prompt_activationcode()
        activationcode = activationcode.strip()
        if len(activationcode) != 9:
            raise ApplicationError("Ongeldige activatiecode - afgebroken.")

        msg("")
        msg("DigiD server query: CreateActivationCodeSession")
        self._cli.create_activation_code_session(self.settings)

        self._authentication_flow(letter_activation=True)

        msg("DigiD server query: CompleteLetterActivation")
        self._cli.complete_letter_activation(activationcode.upper())

        msg("")
        msg("Activatie geslaagd (login_level={})."
            .format(self.settings.login_level))
        msg("De 'authenticate' functie is nu beschikbaar.")
        self.settings.activation_status = "activated"
        self.save_settings()

    def _authentication_flow(self, letter_activation):
        """Doorloop het authenticatie proces."""

        msg = self._ui.msg
        msg("DigiD server query: AuthenticateChallenge")
        resp = self._cli.authenticate_challenge(self.settings)

        challenge = resp.get("challenge")
        iv = resp.get("iv")
        webservice = resp.get("webservice")
        action = resp.get("action")
        authentication_level = resp.get("authentication_level")

        if not challenge:
            raise ApiError("AuthenticateChallenge did not return 'challenge'")
        if not iv:
            raise ApiError("AuthenticateChallenge did not return 'iv'")

        msg("")
        msg("Authenticatie verzoek:")
        msg("  actie: {}".format(action))
        msg("  webservice: {}".format(webservice))
        msg("  authentication level: {}".format(authentication_level))

        if letter_activation:
            if webservice:
                raise ApplicationError(
                    "Onverwachte 'webservice' {!r}".format(webservice))
            if action != "activation_by_letter":
                raise ApplicationError(
                    "Onverwachte 'action' {!r}".format(action))
        else:
            try:
                if int(authentication_level) > self.settings.login_level:
                    msg("WAARSCHUWING: Gevraagd authenticatie niveau is "
                        + "hoger dan login level ({})."
                          .format(self.settings.login_level))
            except ValueError:
                msg("WAARSCHUWING: Onbekend authenticatie niveau gevraagd.")

        msg("")
        msg("Controleer of u bovenstaande authenticatie wilt bevestigen.")
        msg("Druk anders op Ctrl-C om af te breken.")
        msg("")
        msg("Voer uw pincode in (5 cijfers) om authenticatie te bevestigen.")

        while True:
            pincode = self._ui.prompt_pincode()
            if valid_pincode(pincode):
                break
            msg("Ongeldige pincode, probeer opnieuw.")
        msg("")

        signed_challenge = ec_sign(self.settings.private_key, challenge)
        masked_pincode = mask_pincode(self.settings.mask_code, pincode)
        masked_pincode = encrypt_pincode(self.settings.symmetric_key,
                                         iv,
                                         masked_pincode)

        msg("DigiD server query: Authenticate")
        resp = self._cli.authenticate(self.settings,
                                      signed_challenge,
                                      masked_pincode)

        authentication_level = resp.get("authentication_level")
        if isinstance(authentication_level, int):
            self.settings.login_level = authentication_level

    def _parse_qrcode(self, qrcode):
        """Verwerk de gescande QR code.

        Geef als resultaat een dict van key/value paren uit de code.
        """

        data = {}
        if not qrcode.startswith("digid-app-auth:"):
            raise ApplicationError("Ongeldige QR code")
        remain = qrcode[15:]
        if remain.startswith("//"):
            remain = remain[2:]
        frags = remain.split("&")
        for frag in frags:
            w = frag.split("=", 1)
            if len(w) != 2:
                raise ApplicationError("Ongeldige QR code")
            data[w[0]] = w[1]
        return data

    def authenticate(self):
        """Start de authenticatie functie (om in te loggen op een website)."""

        msg = self._ui.msg
        self.check_version()
        self.load_settings()

        if self.settings is None:
            raise ApplicationError(
                "Authenticatie niet mogelijk - geen instellingen gevonden")
        if self.settings.activation_status != "activated":
            msg("Onverwachte actievatiestatus in instellingen: {}"
                .format(self.settings.activation_status))
            raise ApplicationError(
                "Authenticatie niet mogelijk - app is nog niet geactiveerd")

        koppelcode = make_koppelcode()

        msg("")
        msg("Voer de koppelcode in op de website waar u wilt inloggen.")
        self._ui.show_koppelcode(koppelcode)
        msg("")

        qrcode = self._ui.get_qrcode()
        log("QR code: " + qrcode)

        qrdata = self._parse_qrcode(qrcode)
        qrhost = qrdata.get("host")
        app_session_id = qrdata.get("app_session_id")
        persistcookie = qrdata.get("lb")
        verification_code = qrdata.get("verification_code")
        qrtimestamp = qrdata.get("at")

        if qrhost and qrhost != "digid.nl":
            raise ApplicationError(
                "Ongeldige 'host' in QR code (host={!r})".format(qrhost))

        if not app_session_id:
            raise ApplicationError(
                "Veld 'app_session_id' ontbreekt in QR code")

        if qrtimestamp:
            try:
                tsval = float(qrtimestamp)
            except ValueError:
                raise ApplicationError(
                    "Ongeldige timestamp ('at' veld) in QR code")
            if time.time() > tsval + 15 * 60:
                raise ApplicationError(
                    "QR code is ouder dan 15 minuten (at={})".format(tsval))

        if not verification_code:
            raise ApplicationError(
                "Veld 'verification_code' ontbreekt in QR code")
        if verification_code != koppelcode:
            raise ApplicationError(
                "Verkeerde koppelcode in QR code ({})"
                .format(verification_code))

        self._cli.set_session_id(app_session_id)
        if persistcookie:
            self._cli.set_persistcookie(persistcookie)

        self._authentication_flow(letter_activation=False)

        msg("")
        msg("Authenticatie geslaagd.")


def main():
    global opt_verbose

    parser = argparse.ArgumentParser()
    parser.format_help = lambda: __doc__ + "\n"
    parser.format_usage = lambda: __doc__ + "\n"

    parser.add_argument("mode", type=str, nargs="?")
    parser.add_argument("--verbose", action="store_true")

    args = parser.parse_args()

    if (not args.mode) or (args.mode.lower() == "help"):
        parser.print_usage()
        sys.exit(0)

    if args.verbose:
        opt_verbose = True

    try:
        if args.mode not in ("status",
                             "checkversion",
                             "activate",
                             "complete",
                             "authenticate"):
            raise ApplicationError("Onbekende actie '{}'".format(args.mode))

        app = DigidApp()

        if args.mode == "status":
            app.status()
        elif args.mode == "checkversion":
            app.check_version()
        elif args.mode == "activate":
            app.activate()
        elif args.mode == "complete":
            app.complete()
        elif args.mode == "authenticate":
            app.authenticate()

    except ApplicationError as exc:
        print("FOUT: {}".format(exc), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

