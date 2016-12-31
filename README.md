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

let text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."

var publicKey: SecKey
var privateKey: SecKey

// Key pair generation
(publicKey, privateKey) = try! RSA.generateKeyPair(withSize: 2048)

print("Public key: \(publicKey)\nPrivate key: \(privateKey)\n")

// Encryption
let encryptedData = try! RSA.encrypt(data: text.data(using: .utf8)!, using: publicKey)

print("Encrypted data: \(encryptedData.base64EncodedString())\n")

// Decryption
let decryptedData = try! RSA.decrypt(data: encryptedData, using: privateKey)

print("Decrypted data: \(String(data: decryptedData, encoding: .utf8)!)\n")

// Signing
let signature = try! RSA.sign(encryptedData, using: privateKey, digestAlgorithm: .PKCS1SHA1)

print("Data signature: \(signature.base64EncodedString())\n")

// Verification
let verificationResult = try! RSA.verify(encryptedData, using: publicKey, digestAlgorithm: .PKCS1SHA1, signature: signature)

print("Signature verification result: \(verificationResult)\n")

// Key's data
let data = publicKey.data

print("Key's data: \(data.base64EncodedString())\n")

// Key's PEM
let pem = publicKey.pem

print("Key's PEM: \(pem)\n")

// Creating a key from data
let publicKeyFromData = try! SecKey.make(from: data, isPublicKey: true)

print("Public key from data: \(publicKeyFromData)\n")

// Creating a key from PEM
let publicKeyFromPEM = try! SecKey.make(fromPEM: pem, isPublicKey: true)

print("Public key from PEM: \(publicKeyFromPEM)\n")
```
