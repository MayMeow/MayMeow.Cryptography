![.NET Core](https://github.com/MayMeow/MayMeow.Cryptography/workflows/.NET%20Core/badge.svg)

# MayMeow.Cryptography

Wrapper arround .NET Cryptography library.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/D1D5DMOTA)

## Installation

This library can be installed to your project with NuGet package manager

```powershell
Install-Package MayMeow.Cryptography -Version 1.1.0
```

or with dotnet cli

```powershell
dotnet add package MayMeow.Cryptography --version 1.1.0
```

For more installation methods refer [NuGet page](https://www.nuget.org/packages/MayMeow.Cryptography) of this project.

## Usage

### Using this library

Use in you project

```csharp
using MayMeow.Cryptography;
```

### AES encryption (symmetric one)

- Symmetric-key algorithm
- Approved and used by NSA
- Much faster than DES and 3DES for bulk data encryption.
- Original name is **Rijndael**, named to AES after [Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard_process) contest.

Initialize aes and generate new key and IV. AES is an symmetric encryption which using same key to encrypt and decrypt.

```csharp
AES aes = new AES();

string AesKey = aes.GetAesKey();
string AesIV = aes.GetIV();
```

To encrypt your text use

```csharp
string AesEncrypted = AES.Encrypt(message, AesKey, AesIV);
```

and simillarly to decrypt use

```csharp
string AesDecrypted = AES.Decrypt(AesEncrypted, AesKey);
```

Example above using generated and unprotected key for your encryption. 

### RSA Encryption (asymmetric one)

- Achieving strong encryption through the use of two large prime numbers [Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- Encrypts your data with public key
- Decrypts your data with private key
- **Solves** I want anybody to be able to encrypt a message, but I'm the only one who can decrypt it. I don't want to share decryption keys with anybody.

First initialize RSA and create your public and private key

```csharp
RSA rsa = new RSA(RSA.KEY_SIZE);

string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());
```

Now encryption is easy as

```csharp
string message = "Hello world";
string encryptedText = RSA.Encrypt(message, RSA.SetKeyFromString(pubKey));
string plainText = RSA.Decrypt(encryptedText, RSA.SetKeyFromString(privKey));
```

### AES GCM encryption with protected key (combination of asymmetric and symmetric one)

This is more advande example where key for encryption is protected with RSA. RSA is asymetric encryption where public key is used for encryption your data and for decryption is used private key, which is in most time also protected by password. :warning: Do not share your private key with anyone!

#### Initialize RSA keys

```csharp
RSA rsa = new RSA(RSA.KEY_SIZE);

string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());
```

Initialize key and aad for GCM encryption

```csharp
// Create AES Keys
byte[] key = new byte[16];
RandomNumberGenerator.Fill(key);

byte[] aad = new byte[32];
RandomNumberGenerator.Fill(aad);
```

Now secure your key

```csharp
byte[] encryptedAeskey = RSA.EncryptBytes(key, RSA.SetKeyFromString(pubKey));
```

before using it you have to decrypt it

```csharp
byte[] decryptedAesKey = RSA.DecryptBytes(encryptedAeskey, RSA.SetKeyFromString(privKey));
```

Key above was secured with asymmetric cryptography. **Never share your private key with anyone.**

Now encryption is simmilar as in our first example

```csharp
byte[] encryptedData = GCM.Encrypt(dataToEncrypt, key, aad);
byte[] decryptedData = GCM.Decrypt(encryptedData, decryptedAesKey, aad);
```

If you want to encrypt string you have to do it as follows

```csharp
byte[] encryptedStringData = GCM.Encrypt(Encoding.UTF8.GetBytes(stringToEncrypt), key, aad);
```

For decryption is it same as above.

## Sign and verify data using RSA (a.k.a. Digital signature)

- Sign data using private key
- Verify data using public key
- Usually used in cases where it is important to detect forgery or tampering
- Provides cryptographic way of Authentication, Integrity, Non-repudiation

For more information check this [Wikipedia](https://en.wikipedia.org/wiki/Digital_signature) page.

### Initialize RSA parameters (a.k.a. get your keys)

First you will need to get your public and private key. You can do this as in  [RSA encryption](#rsa-encryption-asymmetric-one). Or you can use random generated one as follows:

```csharp
RSA rsa = new RSA(RSA.KEY_SIZE);
RSAParameters key = rsa.GetRSAParameters(true);
```

method above will be available from version `1.3.0` for all RSA related tasks.

Now you can Sign your data like follows. (You are signing your data with your private key)

```csharp
byte[] signedData = RSA.HashAndSignBytes(dataToSign, key);

// if you using method with keys provided from string use
byte[] signedData = RSA.HashAndSignBytes(dataToSign, RSA.SetKeyFromString(privKey));
```

And for verification use following lines (You are verifying your data with your Public key)

```csharp
// will be TRUE if your data wasn't modified from time of your signature, otherwise it will be FALSE
bool isVerified = RSA.VerifySignedHash(dataToSign, key);

// if you using method with keys provided from string use
bool isVerified = RSA.VerifySignedHash(dataToSign, RSA.SetKeyFromString(pubKey));
```

## Key derivation with PBKDF2

This function is used to derive you key (for example for unlocking private key) from your password. You can read more about it on [Wikipedia](https://en.wikipedia.org/wiki/PBKDF2)

to derive key use following snippet

```csharp
// string password = "my$up3r$3cr3tP4$$w0rd1";
// string salt = "8VySCxa42j9McSqGjZxCVQnH4x4rSZszEL9YQT3VkZ75xbBD";
var derivedKey = PBKDF2.keyDerivate(password, salt, 1024, 10);
```

## Symmetric Encryption Manager

The `SymmetricEncryptionManager` provides a high-level, secure implementation of AES-256 symmetric encryption with password-based key derivation. This class is designed for developers who need strong encryption without dealing with low-level cryptographic details.

### Security Features

- **AES-256 encryption** with CBC mode and PKCS7 padding
- **PBKDF2-SHA256 key derivation** with 100,000 iterations for password-to-key conversion
- **Unique salt and IV generation** for each encryption operation
- **Secure random password generation** capability
- **Integrated data structure** that includes all parameters needed for decryption

### Basic Usage

#### Encrypting and Decrypting Data

```csharp
using MayMeow.Cryptography.Security;

// Generate a secure password
string password = SymmetricEncryptionManager.GenerateRandomPassword();
string dataToEncrypt = "Sensitive information to protect";

// Encrypt the data
var encryptedData = SymmetricEncryptionManager.encryptData(password, dataToEncrypt);

// Convert to Base64 for storage or transmission
string base64Encrypted = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(encryptedData);

// Later, retrieve and decrypt the data
var retrievedData = SymmetricEncryptionManager.EncryptedDataExtensions.FromBase64(base64Encrypted);
string decryptedText = SymmetricEncryptionManager.decryptData(retrievedData, password);

Console.WriteLine($"Original: {dataToEncrypt}");
Console.WriteLine($"Decrypted: {decryptedText}");
// Both strings will be identical
```

#### Using Your Own Password

```csharp
string myPassword = "MyStrongPassword123!";
string message = "Secret message";

// Encrypt with your password
var encrypted = SymmetricEncryptionManager.encryptData(myPassword, message);

// Decrypt with the same password
string decrypted = SymmetricEncryptionManager.decryptData(encrypted, myPassword);
```

#### Error Handling

```csharp
try
{
    var encryptedData = /* ... load from storage ... */;
    string password = /* ... get from user ... */;
    
    string decryptedText = SymmetricEncryptionManager.decryptData(encryptedData, password);
    Console.WriteLine($"Successfully decrypted: {decryptedText}");
}
catch (CryptographicException)
{
    Console.WriteLine("Decryption failed - incorrect password or corrupted data");
}
catch (ArgumentException ex)
{
    Console.WriteLine($"Invalid input: {ex.Message}");
}
```

### Advanced Usage

#### Working with Base64 Serialization

The `EncryptedDataExtensions` class provides convenient methods for converting encrypted data to and from Base64 strings for storage or transmission:

```csharp
// Encrypt data
var encryptedData = SymmetricEncryptionManager.encryptData(password, "data");

// Convert to Base64 for database storage
string base64String = SymmetricEncryptionManager.EncryptedDataExtensions.ToBase64(encryptedData);

// Store in database, file, or send over network
SaveToDatabase(base64String);

// Later, retrieve and convert back
string retrievedBase64 = LoadFromDatabase();
var retrievedData = SymmetricEncryptionManager.EncryptedDataExtensions.FromBase64(retrievedBase64);

// Decrypt
string decryptedData = SymmetricEncryptionManager.decryptData(retrievedData, password);
```

#### Accessing Cryptographic Parameters

The `EncryptedData` class contains all the cryptographic parameters used during encryption:

```csharp
var encryptedData = SymmetricEncryptionManager.encryptData(password, "data");

Console.WriteLine($"Salt length: {encryptedData.Salt.Length} bytes");
Console.WriteLine($"IV length: {encryptedData.IV.Length} bytes");
Console.WriteLine($"Iterations: {encryptedData.Iterations}");
Console.WriteLine($"Cipher data length: {encryptedData.CipherData.Length} bytes");
```

### Security Best Practices

#### Password Guidelines

- **Use strong passwords**: Minimum 12 characters with mixed case, numbers, and symbols
- **Use unique passwords**: Don't reuse encryption passwords across different contexts
- **Consider generated passwords**: Use `GenerateRandomPassword()` for maximum security
- **Secure password storage**: Store passwords using secure password management practices

#### Data Protection

- **Protect encrypted data**: Store encrypted data securely to prevent tampering
- **Verify integrity**: Consider additional integrity checks for critical data
- **Secure transmission**: Use secure channels (HTTPS/TLS) when transmitting encrypted data
- **Key rotation**: Periodically re-encrypt data with new passwords for long-term storage

#### Implementation Notes

- **Salt and IV uniqueness**: Each encryption operation generates a unique salt and IV automatically
- **No password reuse detection**: The system doesn't prevent password reuse - this is application responsibility
- **Memory security**: Consider secure memory handling for sensitive passwords in production applications
- **Performance**: PBKDF2 with 100,000 iterations may take ~100ms per operation - consider this for high-frequency scenarios

### Technical Details

- **Algorithm**: AES-256 in CBC mode with PKCS7 padding
- **Key Derivation**: PBKDF2-SHA256 with 100,000 iterations
- **Salt Size**: 16 bytes (128 bits)
- **IV Size**: 16 bytes (128 bits)
- **Key Size**: 32 bytes (256 bits)
- **Generated Password Entropy**: 256 bits (32 random bytes, Base64 encoded)

### Exception Handling

The SymmetricEncryptionManager methods can throw the following exceptions:

- `ArgumentException`: When passwords are null or empty
- `ArgumentNullException`: When encrypted data objects are null
- `CryptographicException`: When decryption fails due to wrong password or corrupted data
- `FormatException`: When Base64 strings are invalid during conversion

Always wrap encryption/decryption operations in appropriate try-catch blocks to handle these exceptions gracefully.

License MIT
