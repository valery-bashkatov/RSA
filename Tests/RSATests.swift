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
    
    var keyPair: (publicKey: SecKey, privateKey: SecKey)!
    
    override func setUp() {
        super.setUp()

        keyPair = try! RSA.generateKeyPair(size: 2048)
    }
    
    func testPublicKeyNotNil() {
        XCTAssertNotNil(keyPair.publicKey)
    }
    
    func testPrivateKeyNotNil() {
        XCTAssertNotNil(keyPair.privateKey)
    }
    
    func testPublicKeySize512() {
        keyPair = try! RSA.generateKeyPair(size: 512)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 512 bits")})
    }
    
    func testPublicKeySize768() {
        keyPair = try! RSA.generateKeyPair(size: 768)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 768 bits")})
    }
    
    func testPublicKeySize1024() {
        keyPair = try! RSA.generateKeyPair(size: 1024)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 1024 bits")})
    }
    
    func testPublicKeySize2048() {
        keyPair = try! RSA.generateKeyPair(size: 2048)
        
        XCTAssertTrue("\(keyPair.publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("block size: 2048 bits")})
    }
}
