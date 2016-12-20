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
    
    override func setUp() {
        super.setUp()

        keyPair = try! RSA.generateKeyPair(withSize: 2048)
    }
    
    func testPublicKeyNotNill() {
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("key type: RSAPublicKey")})
    }
    
    func testPrivateKeyNotNill() {
        XCTAssertTrue("\(keyPair.privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("key type: RSAPrivateKey")})
    }
    
    func testPublicKeySize512() {
        keyPair = try! RSA.generateKeyPair(withSize: 512)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 512 bits")})
    }
    
    func testPublicKeySize768() {
        keyPair = try! RSA.generateKeyPair(withSize: 768)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 768 bits")})
    }
    
    func testPublicKeySize1024() {
        keyPair = try! RSA.generateKeyPair(withSize: 1024)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 1024 bits")})
    }
    
    func testPublicKeySize2048() {
        keyPair = try! RSA.generateKeyPair(withSize: 2048)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 2048 bits")})
    }
    
    func testEncryptedDataNotEmpty() {
        let encryptedData = try! RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        
        XCTAssertTrue(!encryptedData.isEmpty)
    }
    
    func testDecryptedDataNotEmpty() {
        let encryptedData = try! RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        let decryptedData = try! RSA.decrypt(data: encryptedData, using: keyPair.privateKey)
        
        XCTAssertTrue(!decryptedData.isEmpty)
    }
    
    func testEncryptDecrypt() {
        let encryptedData = try! RSA.encrypt(data: text.data(using: .utf8)!, using: keyPair.publicKey)
        let decryptedData = try! RSA.decrypt(data: encryptedData, using: keyPair.privateKey)
        
        XCTAssertEqual(String(data: decryptedData, encoding: .utf8), text)
    }
    
    func testPublicKeyDataNotEmpty() {
        XCTAssertTrue(!keyPair.publicKey.data.isEmpty)
    }
    
    func testPrivateKeyDataNotEmpty() {
        XCTAssertTrue(!keyPair.privateKey.data.isEmpty)
    }
}
