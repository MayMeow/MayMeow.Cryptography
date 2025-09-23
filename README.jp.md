![.NET Core](https://github.com/MayMeow/MayMeow.Cryptography/workflows/.NET%20Core/badge.svg)

# MayMeow.Cryptography

.NET の暗号化ライブラリを扱うラッパーです。

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/D1D5DMOTA)

## インストール

このライブラリは NuGet パッケージ マネージャーでプロジェクトにインストールできます。

```powershell
Install-Package MayMeow.Cryptography -Version 1.1.0
```

または dotnet CLI でもインストールできます。

```powershell
dotnet add package MayMeow.Cryptography --version 1.1.0
```

その他のインストール方法については本プロジェクトの [NuGet ページ](https://www.nuget.org/packages/MayMeow.Cryptography)をご参照ください。

## 使い方

### このライブラリを使う

プロジェクトで次のように using を追加します。

```csharp
using MayMeow.Cryptography;
```

### AES 暗号化（共通鍵方式）

- 共通鍵暗号方式です
- NSA により承認・使用されています
- 大量データの暗号化において DES や 3DES より高速です
- 元の名称は「Rijndael」で、[Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard_process) の選定後に AES として名付けられました

AES を初期化し、新しいキーと IV を生成します。AES は暗号化と復号に同じ鍵を使用する共通鍵暗号です。

```csharp
AES aes = new AES();

string AesKey = aes.GetAesKey();
string AesIV = aes.GetIV();
```

暗号化は次のように行います。

```csharp
string AesEncrypted = AES.Encrypt(message, AesKey, AesIV);
```

復号は次のとおりです。

```csharp
string AesDecrypted = AES.Decrypt(AesEncrypted, AesKey);
```

上記の例では、生成した未保護の鍵をそのまま暗号化に使用しています。

### RSA 暗号化（公開鍵方式）

- 2 つの大きな素数を用いて強力な暗号化を実現します [Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- 公開鍵でデータを暗号化します
- 秘密鍵でデータを復号します
- 「誰でもメッセージを暗号化できるが、復号できるのは自分だけにしたい。復号鍵は誰とも共有したくない」といった要件を満たします

まず RSA を初期化し、公開鍵と秘密鍵を作成します。

```csharp
RSA rsa = new RSA(RSA.KEY_SIZE);

string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());
```

暗号化と復号は次のように簡単に行えます。

```csharp
string message = "Hello world";
string encryptedText = RSA.Encrypt(message, RSA.SetKeyFromString(pubKey));
string plainText = RSA.Decrypt(encryptedText, RSA.SetKeyFromString(privKey));
```

### 保護された鍵による AES GCM 暗号化（公開鍵方式と共通鍵方式の組み合わせ）

これは、暗号化に使用する鍵自体を RSA で保護する、より高度な例です。RSA は公開鍵暗号で、公開鍵で暗号化し、復号は（多くの場合パスワードで保護された）秘密鍵で行います。重要：秘密鍵は決して共有しないでください。

#### RSA 鍵の初期化

```csharp
RSA rsa = new RSA(RSA.KEY_SIZE);

string pubKey = TextConversion.Base64Encode(rsa.GetPublicKey());
string privKey = TextConversion.Base64Encode(rsa.GetPrivateKey());
```

GCM 暗号化に用いる鍵と AAD を初期化します。

```csharp
// Create AES Keys
byte[] key = new byte[16];
RandomNumberGenerator.Fill(key);

byte[] aad = new byte[32];
RandomNumberGenerator.Fill(aad);
```

次に、鍵を保護します。

```csharp
byte[] encryptedAeskey = RSA.EncryptBytes(key, RSA.SetKeyFromString(pubKey));
```

使用前に復号します。

```csharp
byte[] decryptedAesKey = RSA.DecryptBytes(encryptedAeskey, RSA.SetKeyFromString(privKey));
```

上記の鍵は公開鍵暗号で保護されています。秘密鍵は決して共有しないでください。

暗号化・復号は最初の例と同様です。

```csharp
byte[] encryptedData = GCM.Encrypt(dataToEncrypt, key, aad);
byte[] decryptedData = GCM.Decrypt(encryptedData, decryptedAesKey, aad);
```

文字列を暗号化する場合は次のとおりです。

```csharp
byte[] encryptedStringData = GCM.Encrypt(Encoding.UTF8.GetBytes(stringToEncrypt), key, aad);
```

復号も同様です。

## RSA を用いた署名と検証（いわゆるデジタル署名）

- 秘密鍵でデータに署名します
- 公開鍵で署名を検証します
- なりすましや改ざんの検知が重要なケースでよく使われます
- 認証・完全性・否認防止を暗号的に提供します

詳細は [Wikipedia](https://en.wikipedia.org/wiki/Digital_signature) をご参照ください。

### RSA パラメータの初期化（鍵の取得）

まず公開鍵と秘密鍵を用意します。やり方は [RSA 暗号化](#rsa-encryption-asymmetric-one) と同様です。あるいは、次のようにランダムに生成したものを使うこともできます。

```csharp
RSA rsa = new RSA(RSA.KEY_SIZE);
RSAParameters key = rsa.GetRSAParameters(true);
```

上記のメソッドは、`1.3.0` 以降のバージョンで、RSA 関連のタスクすべてでご利用いただけます。

次に、以下のようにデータへ署名します（秘密鍵で署名します）。

```csharp
byte[] signedData = RSA.HashAndSignBytes(dataToSign, key);

// if you using method with keys provided from string use
byte[] signedData = RSA.HashAndSignBytes(dataToSign, RSA.SetKeyFromString(privKey));
```

検証は次のとおりです（公開鍵で検証します）。

```csharp
// will be TRUE if your data wasn't modified from time of your signature, otherwise it will be FALSE
bool isVerified = RSA.VerifySignedHash(dataToSign, key);

// if you using method with keys provided from string use
bool isVerified = RSA.VerifySignedHash(dataToSign, RSA.SetKeyFromString(pubKey));
```

## PBKDF2 による鍵導出

この機能は、パスワードから鍵（例：秘密鍵のロック解除用）を導出するために使用します。詳細は [Wikipedia](https://en.wikipedia.org/wiki/PBKDF2) をご参照ください。

鍵を導出するには、次のスニペットを使用します。

```csharp
// string password = "my$up3r$3cr3tP4$$w0rd1";
// string salt = "8VySCxa42j9McSqGjZxCVQnH4x4rSZszEL9YQT3VkZ75xbBD";
var derivedKey = PBKDF2.keyDerivate(password, salt, 1024, 10);
```

License MIT