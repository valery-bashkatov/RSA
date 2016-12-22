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
    var keyPair: (publicKey: SecKey, privateKey: SecKey)!
    
    // MARK: - Helpers
    
    private func isEqual(firstPublicKey: SecKey?, secondPublicKey: SecKey?) -> Bool {
        
        let expectedModulus = "\(secondPublicKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("modulus: ")}
        
        let modulus = "\(firstPublicKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("modulus: ")}
        
        return modulus == expectedModulus
    }
    
    private func isEqual(firstPrivateKey: SecKey?, secondPrivateKey: SecKey?) -> Bool {
        
        let expectedKeyType = "\(secondPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("key type: ")}
        
        let expectedKeySize = "\(secondPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("block size: ")}
        
        
        let keyType = "\(firstPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("key type: ")}
        
        let keySize = "\(firstPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("block size: ")}
        
        return keyType == expectedKeyType && keySize == expectedKeySize
    }
    
    // MARK: - Tests
    
    override func setUp() {
        super.setUp()
        
        do {
            keyPair = try RSA.generateKeyPair(withSize: 2048)
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testPublicKey() {
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("key type: RSAPublicKey")})
    }
    
    func testPrivateKey() {
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("key type: RSAPrivateKey")})
    }
    
    func testKeySize512() {
        do {
            keyPair = try RSA.generateKeyPair(withSize: 512)
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 512 bits")})
        
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 512 bits")})
    }
    
    func testKeySize768() {
        do {
            keyPair = try RSA.generateKeyPair(withSize: 768)
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 768 bits")})
        
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 768 bits")})
    }
    
    func testKeySize1024() {
        do {
            keyPair = try RSA.generateKeyPair(withSize: 1024)
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 1024 bits")})
    
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 1024 bits")})
    }
    
    func testKeySize2048() {
        do {
            keyPair = try RSA.generateKeyPair(withSize: 2048)
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 2048 bits")})
        
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 2048 bits")})
    }
    
    func testEncrypt() {
        var encryptedData = Data()
        
        do {
            encryptedData = try RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        } catch {
            XCTFail("Data encryption failed: \(error)")
        }
        
        XCTAssertTrue(!encryptedData.isEmpty)
    }
    
    func testDecrypt() {
        var encryptedData = Data()
        var decryptedData = Data()
        
        do {
            encryptedData = try RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        } catch {
            XCTFail("Data encryption failed: \(error)")
        }
        
        do {
            decryptedData = try RSA.decrypt(data: encryptedData, using: keyPair.privateKey)
        } catch {
            XCTFail("Data decryption failed: \(error)")
        }
        
        XCTAssertTrue(!decryptedData.isEmpty)
    }
    
    func testEncryptDecrypt() {
        var encryptedData = Data()
        var decryptedData = Data()
        
        do {
            encryptedData = try RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        } catch {
            XCTFail("Data encryption failed: \(error)")
        }
        
        do {
            decryptedData = try RSA.decrypt(data: encryptedData, using: keyPair.privateKey)
        } catch {
            XCTFail("Data decryption failed: \(error)")
        }
        
        XCTAssertEqual(String(data: decryptedData, encoding: .utf8), text)
    }
    
    func testPublicKeyData() {
        XCTAssertTrue(!keyPair.publicKey.data.isEmpty)
    }
    
    func testPrivateKeyData() {
        XCTAssertTrue(!keyPair.privateKey.data.isEmpty)
    }
    
    func testPublicKeyAttributes() {
        let attributes = keyPair.publicKey.attributes
        
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
        let attributes = keyPair.privateKey.attributes
        
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
        let expectedPem = "-----BEGIN PUBLIC KEY-----\n" +
            keyPair.publicKey.data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
            "\n-----END PUBLIC KEY-----"
        
        let pem = keyPair.publicKey.pem

        XCTAssertEqual(pem, expectedPem)
    }
    
    func testPrivateKeyPEM() {
        let expectedPem = "-----BEGIN PRIVATE KEY-----\n" +
            keyPair.privateKey.data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
            "\n-----END PRIVATE KEY-----"
        
        let pem = keyPair.privateKey.pem
        
        XCTAssertEqual(pem, expectedPem)
    }
    
    func testMakePublicKeyFromData() {
        let data = keyPair.publicKey.data
        let publicKey = SecKey.make(from: data, isPublicKey: true)
        
        XCTAssertNotNil(publicKey)
        XCTAssertTrue(isEqual(firstPublicKey: keyPair.publicKey, secondPublicKey: publicKey))
    }
    
    func testMakePrivateKeyFromData() {
        let data = keyPair.privateKey.data
        let privateKey = SecKey.make(from: data, isPublicKey: false)
        
        XCTAssertNotNil(privateKey)
        XCTAssertTrue(isEqual(firstPrivateKey: keyPair.privateKey, secondPrivateKey: privateKey))
    }
    
    func testMakePublicKeyFromPEM() {
        let pem = keyPair.publicKey.pem
        let publicKey = SecKey.make(fromPEM: pem, isPublicKey: true)
        
        XCTAssertNotNil(publicKey)
        XCTAssertTrue(isEqual(firstPublicKey: keyPair.publicKey, secondPublicKey: publicKey))
    }
    
    func testMakePrivateKeyFromPEM() {
        let pem = keyPair.privateKey.pem
        let privateKey = SecKey.make(fromPEM: pem, isPublicKey: false)
        
        XCTAssertNotNil(privateKey)
        XCTAssertTrue(isEqual(firstPrivateKey: keyPair.privateKey, secondPrivateKey: privateKey))
    }
    
    func testSignSHA1() {
        var signature = Data()
            
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA1)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA224() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA224)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA256() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA256)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA384() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA384)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA512() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA512)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testVerifySHA1() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA1)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(data: text.data(using: .utf8)!, using: keyPair.publicKey, digestType: .PKCS1SHA1, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA224() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA224)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(data: text.data(using: .utf8)!, using: keyPair.publicKey, digestType: .PKCS1SHA224, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA256() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA256)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(data: text.data(using: .utf8)!, using: keyPair.publicKey, digestType: .PKCS1SHA256, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA384() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA384)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(data: text.data(using: .utf8)!, using: keyPair.publicKey, digestType: .PKCS1SHA384, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA512() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(data: text.data(using: .utf8)!, using: keyPair.privateKey, digestType: .PKCS1SHA512)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(data: text.data(using: .utf8)!, using: keyPair.publicKey, digestType: .PKCS1SHA512, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
}
