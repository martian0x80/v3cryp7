# File Encryptor and Decryptor
This is a tool for encrypting and decrypting files using the AES-256 encryption algorithm. The tool takes in a file, encrypts it using a password provided by the user, and outputs the encrypted file. The same password must be provided to decrypt the encrypted file.

How to use
To encrypt a file, run the following command:
```powershell
python encryptor.py -e -i path/to/input/file -o path/to/output/file -p password
```
To decrypt an encrypted file, run the following command:
```powershell
python encryptor.py -d -i path/to/encrypted/file -o path/to/output/file -p password
```
# Dependencies
The Crypto package must be installed. It can be installed using pip:
```
pip install pycrypto
```
The colorama package must be installed. It can be installed using pip:
```
pip install colorama
```
# License
This code is released under the MIT License. See the included LICENSE file for more details.
