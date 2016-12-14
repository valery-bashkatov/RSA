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
 The `Crypto` class contains a set of tools for working with cryptography.
 */
open class RSA {
    
    // MARK: - Initialization
    
    /// :nodoc:
    fileprivate init() {}
    
    // MARK: - Keys Generation
    
    /**
     Generates RSA keys with specified key size.
     
     - parameter size: This value define key size in bits. May have values of 512, 768, 1024, or 2048.
     
     - throws: The `RSAError` if an error occurs.
     
     - returns: A tuple with public and private key.
     */
    static open func generateKeyPair(size: Int) throws -> (publicKey: SecKey, privateKey: SecKey) {
        var publicKey: SecKey?
        var privateKey: SecKey?
        
        var parameters = [String: AnyObject]()
        
        parameters[kSecAttrKeyType as String] = kSecAttrKeyTypeRSA
        parameters[kSecAttrKeySizeInBits as String] = size as AnyObject?
        
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicKey, &privateKey)
        
        guard status == errSecSuccess else {
            throw (RSAError(rawValue: Int(status)) ?? RSAError.unknown)
        }
        
        return (publicKey: publicKey!, privateKey: privateKey!)
    }
    
    /*
    static open func encrypt(text: String, withKey key: SecKey) -> NSData {
        
        let blockSize = SecKeyGetBlockSize(key)
        var messageEncrypted = [UInt8](repeating: 0, count: blockSize)
        var messageEncryptedSize = blockSize
        
        var status: OSStatus!
        
        status = SecKeyEncrypt(key, SecPadding.PKCS1, text, text.characters.count, &messageEncrypted, &messageEncryptedSize)
        
        if status != noErr {
            print("Encryption Error!")
        }
        
        let data = NSData(bytes: messageEncrypted, length: messageEncryptedSize)
        
        return data
    }
    
    static open func decrypt(text: String, withKey key: SecKey) -> String {
        
        let blockSize = SecKeyGetBlockSize(key)
        var messageDecrypted = [UInt8](repeating: 0, count: blockSize)
        var messageDecryptedSize = blockSize
        
        var status: OSStatus!
        
        status = SecKeyDecrypt(key, SecPadding.PKCS1, text, text.characters.count, &messageDecrypted, &messageDecryptedSize)
        
        if status != noErr {
            print("Decryption Error!")
        }
        
        print("Decrypted message: \(NSString(bytes: &messageDecrypted, length: messageDecryptedSize, encoding: String.Encoding.utf8.rawValue)!)")
        
        return ""
    }
    */
    /*
    func encrypt(data: Data, withPublicKey publicKey: SecKey) -> Data {
        
        var encryptedData = [UInt8](repeating: 0, count: SecKeyGetBlockSize(publicKey))
        var encryptedDataSize = encryptedData.count
        
        var status: OSStatus!
        
        status = SecKeyEncrypt(publicKey, .PKCS1, [UInt8](data), data.count, &encryptedData, &encryptedDataSize)
        
        if status != noErr {
            print("Encryption Error!")
        }
        
        return Data(bytes: encryptedData, count: encryptedDataSize)
    }
    
    func decrypt(data: Data, withPrivateKey privateKey: SecKey) -> Data {
        
        var decryptedData = [UInt8](repeating: 0, count: SecKeyGetBlockSize(privateKey))
        var decryptedDataSize = decryptedData.count
        
        var status: OSStatus!
        
        status = SecKeyDecrypt(privateKey, .PKCS1, [UInt8](data), data.count, &decryptedData, &decryptedDataSize)
        
        if status != noErr {
            print("Decryption Error!")
        }
        
        return Data(bytes: decryptedData, count: decryptedDataSize)
    }
    */
}
