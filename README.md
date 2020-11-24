KDCryptoUtils
=====

Collection of various encryption, signing and hashing related utils.

## Components

### Signer

Class for signing and verifying data tampering.

Support for byte, string and JSON data types.

JSON version is immune to changes in keys order.

Example use case - verify data shared over public channels.

### Encrypter

Class for encrypting and decrypting data.

Support for byte, string and JSON data types.

Example use case - encrypting data stored in the database.

### SignedEncrypter

Class for encrypting and decrypting data with tampering prevention support.
Tamper prevention is realized using Signer module.

Support for byte, string and JSON data types.

Example use case - encrypting data sent via emails.

### PasswordHasher

Simple wrapper for PBKDF2. Allows to serialize generated hash to similar (but not compatible) format 
that is used in /etc/shadow.

Example use case - storing password hashes in a database.