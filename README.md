## Pre-requisite

* Need to install dependencies. Use `python3 install.py`.

## Show browser passwords

* This script only works for chromium based browsers like Chrome, Brave, Edge and so on.
* Run the script by `python3 show_browser_password.py`. This shows the UI prompt to select `Login Data` sqlite file. If you are using Chromium based browser, you can check the profile path using `chrome://version`. There will be `Profile path` section. `Login Data` file will be present inside this profile directory.
* In mac, profile directories present inside the library directory. Library directories are hidden when opened in finder. To unhide the hidden directory, use command `cmd + shift + >` in opened prompt.
* After you select the `Login Data` file, the passwords of the selected profile will be printed on the console.

## Refactor

* If libsecret is not present, Chromium uses kwallet in linux. This script only concentrated on libsecret. Need to expand the script to decrypt the password using kwallet.
* If none of the secret storage has been found, Chromium uses `peanuts` as password to generate derived key. [chromium source](https://source.chromium.org/chromium/chromium/src/+/main:components/os_crypt/sync/os_crypt_linux.cc;l=316). Need to handle this case in this script.
* In Windows, legacy algorithm uses direct encryption and decryption of passwords using DPAPI(Data Protection API). Need to handle legacy encryption using DPAPI. As of now, encryption key is stored in `os_crypt.encryption_key` local-state. This key is encoded with base64 algorithm. We can decrypt this and get starting 5 bytes `DPAPI` prefix. If we decrypt the data using DPAPI except this prefix, we will get 16 byte random data, used as key for AEAD crypto algorithm.