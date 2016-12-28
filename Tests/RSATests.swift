//
//  RSATests.swift
//  RSATests
//
//  Created by Valery Bashkatov on 13/12/2016.
//  Copyright © 2016 Valery Bashkatov. All rights reserved.
//

import XCTest
@testable import RSA

class RSATests: XCTestCase {
    
    let text = "RSATests 2016"
    var textData: Data {
        return text.data(using: .utf8)!
    }
    
    var publicKey: SecKey!
    var privateKey: SecKey!
    
    // MARK: - Tests
    
    override func setUp() {
        super.setUp()
        
        do {
            let keyPair = try RSA.generateKeyPair(withSize: 2048)
            
            publicKey = keyPair.publicKey
            privateKey = keyPair.privateKey
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testPublicKey() {
        let keyClass = publicKey.attributes[kSecAttrKeyClass as String] as? Int
        
        XCTAssertEqual(keyClass, Int(kSecAttrKeyClassPublic as String))
    }
    
    func testPrivateKey() {
        let keyClass = privateKey.attributes[kSecAttrKeyClass as String] as? Int
        
        XCTAssertEqual(keyClass, Int(kSecAttrKeyClassPrivate as String))
    }
    
    func testKeySize1024() {
        do {
            var publicKey: SecKey
            var privateKey: SecKey

            (publicKey, privateKey) = try RSA.generateKeyPair(withSize: 1024)
            
            let publicKeySize = publicKey.attributes[kSecAttrKeySizeInBits as String] as? Int
            let privateKeySize = privateKey.attributes[kSecAttrKeySizeInBits as String] as? Int
            
            XCTAssertEqual(publicKeySize, 1024)
            XCTAssertEqual(privateKeySize, 1024)
            
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testKeySize2048() {
        do {
            var publicKey: SecKey
            var privateKey: SecKey
            
            (publicKey, privateKey) = try RSA.generateKeyPair(withSize: 2048)
            
            let publicKeySize = publicKey.attributes[kSecAttrKeySizeInBits as String] as? Int
            let privateKeySize = privateKey.attributes[kSecAttrKeySizeInBits as String] as? Int
            
            XCTAssertEqual(publicKeySize, 2048)
            XCTAssertEqual(privateKeySize, 2048)
            
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testKeySize4096() {
        do {
            var publicKey: SecKey
            var privateKey: SecKey
            
            (publicKey, privateKey) = try RSA.generateKeyPair(withSize: 4096)
            
            let publicKeySize = publicKey.attributes[kSecAttrKeySizeInBits as String] as? Int
            let privateKeySize = privateKey.attributes[kSecAttrKeySizeInBits as String] as? Int
            
            XCTAssertEqual(publicKeySize, 4096)
            XCTAssertEqual(privateKeySize, 4096)
            
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testEncrypt() {
        do {
            var encryptedData = Data()
            
            encryptedData = try RSA.encrypt(data: textData, using: publicKey)
            
            XCTAssertTrue(!encryptedData.isEmpty)
            
        } catch {
            XCTFail("Data encryption failed: \(error)")
        }
    }
    
    func testDecrypt() {
        do {
            var encryptedData = Data()
            var decryptedData = Data()
            
            encryptedData = try RSA.encrypt(data: textData, using: publicKey)
            decryptedData = try RSA.decrypt(data: encryptedData, using: privateKey)
            
            XCTAssertTrue(!decryptedData.isEmpty)
            
        } catch {
            XCTFail("Data decryption failed: \(error)")
        }
    }
    
    func testEncryptDecrypt() {
        do {
            var encryptedData = Data()
            var decryptedData = Data()
            
            encryptedData = try RSA.encrypt(data: textData, using: publicKey)
            decryptedData = try RSA.decrypt(data: encryptedData, using: privateKey)

            XCTAssertEqual(decryptedData, textData)
            
        } catch {
            XCTFail("Data encryption/decryption failed: \(error)")
        }
    }
    
    func testPublicKeyData() {
        XCTAssertTrue(!publicKey.data.isEmpty)
    }
    
    func testPrivateKeyData() {
        XCTAssertTrue(!privateKey.data.isEmpty)
    }
    
    func testPublicKeyAttributes() {
        let attributes = publicKey.attributes
        
        let keyType = attributes[kSecAttrType as String] as? Int
        let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int
        let keyClass = attributes[kSecAttrKeyClass as String] as? Int
        
        XCTAssertNotNil(keyType)
        XCTAssertNotNil(keySize)
        XCTAssertNotNil(keyClass)
        
        XCTAssertEqual(keyType, Int(kSecAttrKeyTypeRSA as String))
        XCTAssertEqual(keySize, 2048)
        XCTAssertEqual(keyClass, Int(kSecAttrKeyClassPublic as String))
    }
    
    func testPrivateKeyAttributes() {
        let attributes = privateKey.attributes
        
        let keyType = attributes[kSecAttrType as String] as? Int
        let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int
        let keyClass = attributes[kSecAttrKeyClass as String] as? Int
        
        XCTAssertNotNil(keyType)
        XCTAssertNotNil(keySize)
        XCTAssertNotNil(keyClass)
        
        XCTAssertEqual(keyType, Int(kSecAttrKeyTypeRSA as String))
        XCTAssertEqual(keySize, 2048)
        XCTAssertEqual(keyClass, Int(kSecAttrKeyClassPrivate as String))
    }
    
    func testPublicKeyPEM() {
        XCTAssertTrue(!publicKey.pem.isEmpty)
    }
    
    func testPrivateKeyPEM() {
        XCTAssertTrue(!privateKey.pem.isEmpty)
    }
    
    func testMakePublicKeyFromData() {
        do {
            let publicKeyFromData = try SecKey.make(from: publicKey.data, isPublicKey: true)
            
            XCTAssertEqual(publicKeyFromData.data, publicKey.data)
            
        } catch {
            XCTFail("Making public key from data failed: \(error)")
        }
    }
    
    func testMakePrivateKeyFromData() {
        do {
            let privateKeyFromData = try SecKey.make(from: privateKey.data, isPublicKey: false)
        
            XCTAssertEqual(privateKeyFromData.data, privateKey.data)
        } catch {
            XCTFail("Making private key from data failed: \(error)")
        }
    }
    
    func testMakePublicKeyFromPEM() {
        do {
            let publicKeyFromPEM = try SecKey.make(fromPEM: publicKey.pem, isPublicKey: true)
            
            XCTAssertEqual(publicKeyFromPEM.data, publicKey.data)
            
        } catch {
            XCTFail("Making public key from PEM failed: \(error)")
        }
    }
    
    func testMakePublicKeyFromOpenSSLPEM() {
        do {
            // OpenSSL PEM format with header
            let openSSLPEM = "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB/2QXG5LFwCOCtnRlVG1OD\n" +
                "styNFJQyN4WZTY0J/NNVuj2pXnZ+EtiOERfa/XwtHLbmXRStmRN8Hoad9Xj8RGMI\n" +
                "9xkftwKBAb58BQaYjPZzj/3ON58sbdlybqVJ+F8TjJHFTgLq6NDGJX9DmJ29PHej\n" +
                "rBkXl/CSeDp5vK+2hSPFhNKj5XPCx4e3YIgvg0/JrnvYTvwabBsTPWZhoA5O9QkK\n" +
                "dRYrar8tl8lWXOyH1bol7nvCnAW5E6yKnxhst2909/+lFVCkTVF9Ng3YPlSQbEaO\n" +
                "RDzi1oxjZeuusJnYMda6IqkUf8ouPYhJIqgjzHEzqC7e393vVYI/BkQzkAPLmB/T\n" +
                "AgMBAAE=\n" +
            "-----END PUBLIC KEY-----"
            
            let publicKeyFromOpenSSLPEM = try SecKey.make(fromPEM: openSSLPEM, isPublicKey: true)
            
            XCTAssertEqual(publicKeyFromOpenSSLPEM.pem, openSSLPEM)
            
        } catch {
            XCTFail("Making public key from OpenSSL PEM failed: \(error)")
        }
    }
    
    func testMakePrivateKeyFromPEM() {
        do {
            let privateKeyFromPEM = try SecKey.make(fromPEM: privateKey.pem, isPublicKey: false)
        
            XCTAssertEqual(privateKeyFromPEM.data, privateKey.data)
            
        } catch {
            XCTFail("Making private key from PEM failed: \(error)")
        }
    }
    
    func testSignSHA1() {
        do {
            var signature = Data()
            
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA1)
            
            XCTAssertTrue(!signature.isEmpty)
            
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
    }
    
    func testSignSHA224() {
        do {
            var signature = Data()
            
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA224)

            XCTAssertTrue(!signature.isEmpty)

        } catch {
            XCTFail("Data signing failed: \(error)")
        }
    }
    
    func testSignSHA256() {
        do {
            var signature = Data()
            
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA256)
            
            XCTAssertTrue(!signature.isEmpty)

        } catch {
            XCTFail("Data signing failed: \(error)")
        }
    }
    
    func testSignSHA384() {
        do {
            var signature = Data()
            
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA384)

            XCTAssertTrue(!signature.isEmpty)

        } catch {
            XCTFail("Data signing failed: \(error)")
        }
    }
    
    func testSignSHA512() {
        do {
            var signature = Data()

            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA512)
            
            XCTAssertTrue(!signature.isEmpty)

        } catch {
            XCTFail("Data signing failed: \(error)")
        }
    }
    
    func testVerifySHA1() {
        do {
            var signature = Data()
            var result = false
            
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA1)
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA1, signature: signature)
            
            XCTAssertTrue(result)
            
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
    }
    
    func testVerifySHA224() {
        do {
            var signature = Data()
            var result = false
            
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA224)
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA224, signature: signature)

            XCTAssertTrue(result)

        } catch {
            XCTFail("Data verification failed: \(error)")
        }
    }
    
    func testVerifySHA256() {
        do {
            var signature = Data()
            var result = false

            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA256)
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA256, signature: signature)
            
            XCTAssertTrue(result)
            
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
    }
    
    func testVerifySHA384() {
        do {
            var signature = Data()
            var result = false

            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA384)
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA384, signature: signature)

            XCTAssertTrue(result)
            
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
    }
    
    func testVerifySHA512() {
        do {
            var signature = Data()
            var result = false

            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA512)
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA512, signature: signature)

            XCTAssertTrue(result)

        } catch {
            XCTFail("Data verification failed: \(error)")
        }
    }
}
