//
//  RSA.swift
//  RSA
//
//  Created by Valery Bashkatov on 13/12/2016.
//  Copyright © 2016 Valery Bashkatov. All rights reserved.
//

import Foundation
import Security

/**
 The `RSA` class provides a set of tools for working with RSA cryptographic algorithm.
 */
open class RSA {
    
    // MARK: - Initialization
    
    /// :nodoc:
    fileprivate init() {}
    
    // MARK: - Keys Generation
    
    /**
     Generates RSA keys with specified key size.
     
     - parameter keySize: This value defines key size in bits. May have values of 512, 768, 1024 or 2048.
     
     - throws: An `RSAError` if an error occurs.
     
     - returns: A tuple with public and private key.
     */
    static open func generateKeyPair(withSize keySize: Int) throws -> (publicKey: SecKey, privateKey: SecKey) {
        var publicKey: SecKey?
        var privateKey: SecKey?
        
        let parameters = [
            (kSecAttrKeyType as String): kSecAttrKeyTypeRSA,
            (kSecAttrKeySizeInBits as String): keySize
            ] as CFDictionary
    
        let status = SecKeyGeneratePair(parameters, &publicKey, &privateKey)
        
        guard status == errSecSuccess else {
            throw RSAError(code: Int(status))
        }

        return (publicKey: publicKey!, privateKey: privateKey!)
    }
    
    // MARK: - Encryption and Decryption
    
    /**
     Encrypts data.
     
     - parameter data: The data to be encrypted.
     - parameter publicKey: The public key with which to encrypt the data.
     - parameter padding: The type of padding to use. Default is PKCS1.
     
     - throws: An `RSAError` if an error occurs.
     
     - returns: The encrypted data.
     */
    static open func encrypt(data: Data, using publicKey: SecKey, padding: SecPadding = .PKCS1) throws -> Data {
        var encryptedData = [UInt8](repeating: 0, count: SecKeyGetBlockSize(publicKey))
        var encryptedDataCount = encryptedData.count
        
        let status = SecKeyEncrypt(publicKey, padding, [UInt8](data), data.count, &encryptedData, &encryptedDataCount)
        
        guard status == errSecSuccess else {
            throw RSAError(code: Int(status))
        }
        
        return Data(bytes: encryptedData, count: encryptedDataCount)
    }
    
    /**
     Decrypts data.
     
     - parameter data: The data to be decrypted.
     - parameter privateKey: The private key with which to decrypt the data.
     - parameter padding: The type of padding to use. Default is PKCS1.
     
     - throws: An `RSAError` if an error occurs.
     
     - returns: The encrypted data.
     */
    static open func decrypt(data: Data, using privateKey: SecKey, padding: SecPadding = .PKCS1) throws -> Data {
        var decryptedData = [UInt8](repeating: 0, count: SecKeyGetBlockSize(privateKey))
        var decryptedDataCount = decryptedData.count
        
        let status = SecKeyDecrypt(privateKey, padding, [UInt8](data), data.count, &decryptedData, &decryptedDataCount)
        
        guard status == errSecSuccess else {
            throw RSAError(code: Int(status))
        }
        
        return Data(bytes: decryptedData, count: decryptedDataCount)
    }
    
    // MARK: - Digital Signatures
    
    /**
     Signs a data (digest) using private key and returns a digital signature. The data will be hashed using specified digest algorithm and then signed with private key.
     
     - parameter data: The data to be signed.
     - parameter privateKey: The private key with which to sign the data.
     - parameter digestAlgorithm: The digest algorithm. Available values: PKCS1SHA1, PKCS1SHA224, PKCS1SHA256, PKCS1SHA384 or PKCS1SHA512.
     
     - throws: An `RSAError` if an error occurs.
     
     - returns: The digital signature of data.
     */
    static open func sign(_ data: Data, using privateKey: SecKey, digestAlgorithm: SecPadding) throws -> Data {
        var digest: [UInt8]
        
        switch digestAlgorithm {
        case SecPadding.PKCS1SHA1:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            CC_SHA1([UInt8](data), CC_LONG(data.count), &digest)
            
        case SecPadding.PKCS1SHA224:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            CC_SHA224([UInt8](data), CC_LONG(data.count), &digest)

        case SecPadding.PKCS1SHA256:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            CC_SHA256([UInt8](data), CC_LONG(data.count), &digest)

        case SecPadding.PKCS1SHA384:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
            CC_SHA384([UInt8](data), CC_LONG(data.count), &digest)
            
        case SecPadding.PKCS1SHA512:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            CC_SHA512([UInt8](data), CC_LONG(data.count), &digest)
            
        default:
            throw RSAError(code: 10)
        }
        
        var signature = [UInt8](repeating: 0, count: SecKeyGetBlockSize(privateKey))
        var signatureCount = signature.count
        
        let status = SecKeyRawSign(privateKey, digestAlgorithm, digest, digest.count, &signature, &signatureCount)
        
        guard status == errSecSuccess else {
            throw RSAError(code: Int(status))
        }
        
        return Data(bytes: signature, count: signatureCount)
    }
    
    /**
     Verifies a data (digest) using public key and digital signature. The data will be hashed using specified digest algorithm, and then digest will be verified with public key and signature.
     
     - parameter data: The data for which the signature is being verified
     - parameter publicKey: The public key with which to verify the data.
     - parameter digestAlgorithm: The digest algorithm, which is used to produce a data digest for verifying. Available values: PKCS1SHA1, PKCS1SHA224, PKCS1SHA256, PKCS1SHA384 or PKCS1SHA512.
     - parameter signature: The digital signature to be verified.
     
     - throws: An `RSAError` if an error occurs.
     
     - returns: Result of data verification.
     */
    static open func verify(_ data: Data, using publicKey: SecKey, digestAlgorithm: SecPadding, signature: Data) throws -> Bool {
        var digest: [UInt8]
        
        switch digestAlgorithm {
        case SecPadding.PKCS1SHA1:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
            CC_SHA1([UInt8](data), CC_LONG(data.count), &digest)
            
        case SecPadding.PKCS1SHA224:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
            CC_SHA224([UInt8](data), CC_LONG(data.count), &digest)
            
        case SecPadding.PKCS1SHA256:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
            CC_SHA256([UInt8](data), CC_LONG(data.count), &digest)
            
        case SecPadding.PKCS1SHA384:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
            CC_SHA384([UInt8](data), CC_LONG(data.count), &digest)
            
        case SecPadding.PKCS1SHA512:
            digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
            CC_SHA512([UInt8](data), CC_LONG(data.count), &digest)
            
        default:
            throw RSAError(code: 10)
        }
        
        let status = SecKeyRawVerify(publicKey, digestAlgorithm, digest, digest.count, [UInt8](signature), signature.count)
        
        switch status {
        case errSecSuccess: return true
        case errSSLCrypto: return false
        default: throw RSAError(code: Int(status))
        }
    }
}
