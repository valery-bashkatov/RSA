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
            let keyPair = try RSA.generateKeyPair(withSize: 2048)
            
            publicKey = keyPair.publicKey
            privateKey = keyPair.privateKey
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testPublicKey() {
        XCTAssertTrue("\(publicKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("key type: RSAPublicKey")})
    }
    
    func testPrivateKey() {
        XCTAssertTrue("\(privateKey)"
            .components(separatedBy: ", ")
            .contains {$0.hasPrefix("key type: RSAPrivateKey")})
    }
    
    func testKeySize512() {
        var publicKey512: SecKey
        var privateKey512: SecKey
        
        do {
            (publicKey512, privateKey512) = try RSA.generateKeyPair(withSize: 512)
            
            XCTAssertTrue("\(publicKey512)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 512 bits")})
            
            XCTAssertTrue("\(privateKey512)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 512 bits")})
            
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testKeySize768() {
        var publicKey768: SecKey
        var privateKey768: SecKey
        
        do {
            (publicKey768, privateKey768) = try RSA.generateKeyPair(withSize: 768)
            
            XCTAssertTrue("\(publicKey768)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 768 bits")})
            
            XCTAssertTrue("\(privateKey768)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 768 bits")})
            
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testKeySize1024() {
        var publicKey1024: SecKey
        var privateKey1024: SecKey
        
        do {
            (publicKey1024, privateKey1024) = try RSA.generateKeyPair(withSize: 1024)
            
            XCTAssertTrue("\(publicKey1024)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 1024 bits")})
            
            XCTAssertTrue("\(privateKey1024)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 1024 bits")})
            
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testKeySize2048() {
        var publicKey2048: SecKey
        var privateKey2048: SecKey
        
        do {
            (publicKey2048, privateKey2048) = try RSA.generateKeyPair(withSize: 2048)
            
            XCTAssertTrue("\(publicKey2048)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 2048 bits")})
            
            XCTAssertTrue("\(privateKey2048)"
                .components(separatedBy: ", ")
                .contains {$0.hasPrefix("block size: 2048 bits")})
            
        } catch {
            XCTFail("Keys generation failed: \(error)")
        }
    }
    
    func testEncrypt() {
        var encryptedData = Data()
        
        do {
            encryptedData = try RSA.encrypt(data: textData, using: publicKey)
        } catch {
            XCTFail("Data encryption failed: \(error)")
        }
        
        XCTAssertTrue(!encryptedData.isEmpty)
    }
    
    func testDecrypt() {
        var encryptedData = Data()
        var decryptedData = Data()
        
        do {
            encryptedData = try RSA.encrypt(data: textData, using: publicKey)
        } catch {
            XCTFail("Data encryption failed: \(error)")
        }
        
        do {
            decryptedData = try RSA.decrypt(data: encryptedData, using: privateKey)
        } catch {
            XCTFail("Data decryption failed: \(error)")
        }
        
        XCTAssertTrue(!decryptedData.isEmpty)
    }
    
    func testEncryptDecrypt() {
        var encryptedData = Data()
        var decryptedData = Data()
        
        do {
            encryptedData = try RSA.encrypt(data: textData, using: publicKey)
        } catch {
            XCTFail("Data encryption failed: \(error)")
        }
        
        do {
            decryptedData = try RSA.decrypt(data: encryptedData, using: privateKey)
        } catch {
            XCTFail("Data decryption failed: \(error)")
        }
        
        XCTAssertEqual(decryptedData, textData)
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
        let expectedPem = "-----BEGIN PUBLIC KEY-----\n" +
            publicKey.data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
            "\n-----END PUBLIC KEY-----"
        
        XCTAssertEqual(publicKey.pem, expectedPem)
    }
    
    func testPrivateKeyPEM() {
        let expectedPem = "-----BEGIN PRIVATE KEY-----\n" +
            privateKey.data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
            "\n-----END PRIVATE KEY-----"
        
        XCTAssertEqual(privateKey.pem, expectedPem)
    }
    
    func testMakePublicKeyFromData() {
        let publicKeyFromData = SecKey.make(from: publicKey.data, isPublicKey: true)
        
        XCTAssertNotNil(publicKeyFromData)
        XCTAssertTrue(isEqual(firstPublicKey: publicKeyFromData, secondPublicKey: publicKey))
    }
    
    func testMakePrivateKeyFromData() {
        let privateKeyFromData = SecKey.make(from: privateKey.data, isPublicKey: false)
        
        XCTAssertNotNil(privateKeyFromData)
        XCTAssertTrue(isEqual(firstPrivateKey: privateKeyFromData, secondPrivateKey: privateKey))
    }
    
    func testMakePublicKeyFromPEMWithoutHeader() {
        let publicKeyFromPEMWithoutHeader = SecKey.make(fromPEM: publicKey.pem, isPublicKey: true)
        
        XCTAssertNotNil(publicKeyFromPEMWithoutHeader)
        XCTAssertTrue(isEqual(firstPublicKey: publicKeyFromPEMWithoutHeader, secondPublicKey: publicKey))
    }
    
    func testMakePublicKeyFromPEMWithHeader() {
        let pemWithHeader = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAklgpC1sTwtmTKh6StTyp\n" +
            "qM84s32fpgdVjYvcb9M9VHdj/2PB+dFDnNHnXoe2iRsWl683Dtz0mySFk4wn6fF6\n" +
            "8EO4/Yh999/OvtBpnTkjGUw8IA+mypSiRla8xHJ86iQu2o0lKny97cq1VvMG7yYp\n" +
            "ctl4NSM24P2nIf66boJIVN5f12ZJH7Id81FA70jgKNyEl5gNaMrRk99oL4imnrt9\n" +
            "djZxel8msAISUV/cQLHHBSWTKSWaPJm2xBS470Xj2SuKkZ+VJHIF6t2EiqcJ1xNy\n" +
            "+riY+COifiCYMw4NCfb/8f88+c0+gQFtt0sJ2N2XoEcyefmCdt3fTf2PV5hAiC/4\n" +
            "RQIDAQAB\n" +
        "-----END PUBLIC KEY-----"
        
        let pemWithoutHeader = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBCgKCAQEAklgpC1sTwtmTKh6StTypqM84s32fpgdVjYvcb9M9VHdj/2PB+dFD\n" +
            "nNHnXoe2iRsWl683Dtz0mySFk4wn6fF68EO4/Yh999/OvtBpnTkjGUw8IA+mypSi\n" +
            "Rla8xHJ86iQu2o0lKny97cq1VvMG7yYpctl4NSM24P2nIf66boJIVN5f12ZJH7Id\n" +
            "81FA70jgKNyEl5gNaMrRk99oL4imnrt9djZxel8msAISUV/cQLHHBSWTKSWaPJm2\n" +
            "xBS470Xj2SuKkZ+VJHIF6t2EiqcJ1xNy+riY+COifiCYMw4NCfb/8f88+c0+gQFt\n" +
            "t0sJ2N2XoEcyefmCdt3fTf2PV5hAiC/4RQIDAQAB\n" +
        "-----END PUBLIC KEY-----"
        
        let publicKeyFromPEMWithHeader = SecKey.make(fromPEM: pemWithHeader, isPublicKey: true)
        let publicKeyFromPEMWithoutHeader = SecKey.make(fromPEM: pemWithoutHeader, isPublicKey: true)
        
        XCTAssertNotNil(publicKeyFromPEMWithHeader)
        XCTAssertNotNil(publicKeyFromPEMWithoutHeader)
        
        XCTAssertTrue(isEqual(firstPublicKey: publicKeyFromPEMWithHeader, secondPublicKey: publicKeyFromPEMWithoutHeader))
    }
    
    func testMakePrivateKeyFromPEM() {
        let privateKeyFromPEM = SecKey.make(fromPEM: privateKey.pem, isPublicKey: false)
        
        XCTAssertNotNil(privateKeyFromPEM)
        XCTAssertTrue(isEqual(firstPrivateKey: privateKeyFromPEM, secondPrivateKey: privateKey))
    }
    
    func testSignSHA1() {
        var signature = Data()
            
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA1)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA224() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA224)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA256() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA256)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA384() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA384)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testSignSHA512() {
        var signature = Data()
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA512)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        XCTAssertTrue(!signature.isEmpty)
    }
    
    func testVerifySHA1() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA1)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA1, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA224() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA224)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA224, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA256() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA256)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA256, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA384() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA384)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA384, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
    
    func testVerifySHA512() {
        var signature = Data()
        var result = false
        
        do {
            signature = try RSA.sign(textData, using: privateKey, digestAlgorithm: .PKCS1SHA512)
        } catch {
            XCTFail("Data signing failed: \(error)")
        }
        
        do {
            result = try RSA.verify(textData, using: publicKey, digestAlgorithm: .PKCS1SHA512, signature: signature)
        } catch {
            XCTFail("Data verification failed: \(error)")
        }
        
        XCTAssertTrue(result)
    }
}
