from sys import platform
import pip

all = [
    'plyer'
]

posix = [
    'pyobjus',  # plyer dependency sometimes not installed on mac.
    'pycryptodome',  # Crypto deps
    'pycryptodomex',  # Crypto deps
    'backports.pbkdf2',
    'keyring'  # gi module deps
]

windows = [
    'pywin32',
    'cryptography'
]


def install(packages):
    for package in packages:
        pip.main(['install', package])


if __name__ == '__main__':
    install(all)
    if platform == 'windows':
        install(windows)
    if platform.startswith('linux') or platform == 'darwin':
        install(posix)
