# RSA
Library provides a set of tools for working with RSA cryptographic algorithm.

## Requirements
- iOS 9.0+
- Swift 3.0+

## Installation
### Carthage
To integrate `RSA` into your project using [Carthage](https://github.com/Carthage/Carthage), specify it in your `RSA`:

```
github "valery-bashkatov/RSA" ~> 1.0.0
```
And then follow the [instructions](https://github.com/Carthage/Carthage#if-youre-building-for-ios-tvos-or-watchos) to install the framework.

## Documentation
API Reference is located at [http://valery-bashkatov.github.io/RSA](http://valery-bashkatov.github.io/RSA).

## Sample
```swift
import Security
import RSA

let text = "Lorem ipsum dolor sit amet..."

var publicKey: SecKey
var privateKey: SecKey

// Key pair generation
(publicKey, privateKey) = try! RSA.generateKeyPair(withSize: 2048)

// Encryption
let encryptedData: Data = try! RSA.encrypt(data: text.data(using: .utf8)!, using: publicKey)

// Decryption
let decryptedData: Data = try! RSA.decrypt(data: encryptedData, using: privateKey)

// Signing
let signature: Data = try! RSA.sign(encryptedData, using: privateKey, digestAlgorithm: .PKCS1SHA1)

// Verification
let verificationResult: Bool = try! RSA.verify(encryptedData, using: publicKey, digestAlgorithm: .PKCS1SHA1, signature: signature)

// Key's data
let data: Data = publicKey.data

// Key's PEM
let pem: String = publicKey.pem

// Key creation from data
let publicKeyFromData: SecKey = try! SecKey.make(from: data, isPublicKey: true)

// Key creation from PEM
let publicKeyFromPEM: SecKey = try! SecKey.make(fromPEM: pem, isPublicKey: true)
```
