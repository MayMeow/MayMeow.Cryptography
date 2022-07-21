![.NET Core](https://github.com/MayMeow/MayMeow.Cryptography/workflows/.NET%20Core/badge.svg)

# MayMeow.Cryptography

Wrapper arround .NET Cryptography library.

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

This is more advande example where key for encryption is protected with RSA. RSA is asymetric encryption where public key is used for encryption your data and for decryption is used private key which is in most time also protected by password. Private key has only its owner.

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

## Key derivation with PBKDF2

This function is used to derive you key (for example for unlocking private key) from your password. You can read more about it on [Wikipedia](https://en.wikipedia.org/wiki/PBKDF2)

to derive key use following snippet

```csharp
// string password = "my$up3r$3cr3tP4$$w0rd1";
// string salt = "8VySCxa42j9McSqGjZxCVQnH4x4rSZszEL9YQT3VkZ75xbBD";
var derivedKey = PBKDF2.keyDerivate(password, salt, 1024, 10);
```

License MIT
