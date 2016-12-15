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
    
    // MARK: - Keys Creation
    
    /**
     Generates RSA keys with specified key size.
     
     - parameter keySize: This value defines key size in bits. May have values of 512, 768, 1024, or 2048.
     
     - throws: The `RSAError` if an error occurs.
     
     - returns: A tuple with public and private key.
     */
    static open func generateKeyPair(withSize keySize: Int) throws -> (publicKey: SecKey, privateKey: SecKey) {
        var publicKey: SecKey?
        var privateKey: SecKey?
        
        var parameters = [String: AnyObject]()
        
        parameters[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        parameters[kSecAttrKeySizeInBits as String] = keySize as AnyObject?
        
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        
        guard status == errSecSuccess else {
            throw (RSAError(rawValue: Int(status)) ?? RSAError.unknown)
        }
        
        return (publicKey: publicKey!, privateKey: privateKey!)
    }
    
    // MARK: - Encryption and Decryption
    
    /**
     Encrypts data.
     
     - parameter data: The data to be encrypted.
     - parameter publicKey: The public key with which to encrypt the data.
     - parameter padding: The type of padding to use. Default is PKCS1.
     
     - throws: The `RSAError` if an error occurs.
     
     - returns: The encrypted data.
     */
    static open func encrypt(data: Data, using publicKey: SecKey, padding: SecPadding = .PKCS1) throws -> Data {
        var encryptedData = [UInt8](repeating: 0, count: SecKeyGetBlockSize(publicKey))
        var encryptedDataSize = encryptedData.count
        
        let status = SecKeyEncrypt(publicKey, padding, [UInt8](data), data.count, &encryptedData, &encryptedDataSize)
        
        guard status == errSecSuccess else {
            throw (RSAError(rawValue: Int(status)) ?? RSAError.unknown)
        }
        
        return Data(bytes: encryptedData, count: encryptedDataSize)
    }
    
    /**
     Decrypts data.
     
     - parameter data: The data to be decrypted.
     - parameter privateKey: The private key with which to decrypt the data.
     - parameter padding: The type of padding to use. Default is PKCS1.
     
     - throws: The `RSAError` if an error occurs.
     
     - returns: The encrypted data.
     */
    static open func decrypt(data: Data, using privateKey: SecKey, padding: SecPadding = .PKCS1) throws -> Data {
        var decryptedData = [UInt8](repeating: 0, count: SecKeyGetBlockSize(privateKey))
        var decryptedDataSize = decryptedData.count
        
        let status = SecKeyDecrypt(privateKey, padding, [UInt8](data), data.count, &decryptedData, &decryptedDataSize)
        
        guard status == errSecSuccess else {
            throw (RSAError(rawValue: Int(status)) ?? RSAError.unknown)
        }
        
        return Data(bytes: decryptedData, count: decryptedDataSize)
    }
}
