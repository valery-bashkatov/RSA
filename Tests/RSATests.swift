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
        
        let expectedModulus = "\(firstPublicKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("modulus: ")}
        
        let modulus = "\(secondPublicKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("modulus: ")}
        
        return modulus == expectedModulus
    }
    
    private func isEqual(firstPrivateKey: SecKey?, secondPrivateKey: SecKey?) -> Bool {
        
        let expectedKeyType = "\(firstPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("key type: ")}
        
        let expectedKeySize = "\(firstPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("block size: ")}
        
        
        let keyType = "\(secondPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("key type: ")}
        
        let keySize = "\(secondPrivateKey)"
            .components(separatedBy: ", ")
            .filter {$0.hasPrefix("block size: ")}
        
        return keyType == expectedKeyType && keySize == expectedKeySize
    }
    
    // MARK: - Tests
    
    override func setUp() {
        super.setUp()
        
        keyPair = try! RSA.generateKeyPair(withSize: 2048)
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
        keyPair = try! RSA.generateKeyPair(withSize: 512)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 512 bits")})
        
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 512 bits")})
    }
    
    func testKeySize768() {
        keyPair = try! RSA.generateKeyPair(withSize: 768)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 768 bits")})
        
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 768 bits")})
    }
    
    func testKeySize1024() {
        keyPair = try! RSA.generateKeyPair(withSize: 1024)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 1024 bits")})
    
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 1024 bits")})
    }
    
    func testKeySize2048() {
        keyPair = try! RSA.generateKeyPair(withSize: 2048)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 2048 bits")})
        
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 2048 bits")})
    }
    
    func testEncrypt() {
        let encryptedData = try! RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        
        XCTAssertTrue(!encryptedData.isEmpty)
    }
    
    func testDecrypt() {
        let encryptedData = try! RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        let decryptedData = try! RSA.decrypt(data: encryptedData, using: keyPair.privateKey)
        
        XCTAssertTrue(!decryptedData.isEmpty)
    }
    
    func testEncryptDecrypt() {
        let encryptedData = try! RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        let decryptedData = try! RSA.decrypt(data: encryptedData, using: keyPair.privateKey)
        
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
}
