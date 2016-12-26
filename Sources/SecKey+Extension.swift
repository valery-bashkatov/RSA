//
//  SecKey+Extension.swift
//  RSA
//
//  Created by Valery Bashkatov on 13/12/2016.
//  Copyright © 2016 Valery Bashkatov. All rights reserved.
//

import Foundation
import Security

public extension SecKey {
    
    // MARK: - Properties
    
    /**
     The key's attributes.
     
     List of available attributes:
     [Security Framework Reference. Attribute Item Keys](https://developer.apple.com/reference/security/1658642-keychain_services/1662474-attribute_item_keys)
     */
    public var attributes: [String: AnyObject] {
        
        let query = [
            (kSecClass as String): kSecClassKey,
            (kSecAttrApplicationTag as String): UUID().uuidString,
            (kSecValueRef as String): self,
            (kSecReturnAttributes as String): true
            ] as CFDictionary
        
        var attributes: AnyObject?
        var status: OSStatus
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemAdd(query, &attributes)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        return attributes as! [String: AnyObject]
    }
    
    /// The data of key.
    public var data: Data {
        
        let query = [
            (kSecClass as String): kSecClassKey,
            (kSecAttrApplicationTag as String): UUID().uuidString,
            (kSecValueRef as String): self,
            (kSecReturnData as String): true
            ] as CFDictionary
        
        var data: AnyObject?
        var status: OSStatus
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemAdd(query, &data)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        return data as! Data
    }
    
    /**
     The key in PEM format.
     
     - seealso: [PEM Format Description](http://how2ssl.com/articles/working_with_pem_files/)
     */
    public var pem: String {
        var keyType = " "
        
        if let keyClass = attributes[kSecAttrKeyClass as String] as? Int {
            
            switch keyClass {
            case Int(kSecAttrKeyClassPublic as String)!:
                keyType = " PUBLIC "
                
            case Int(kSecAttrKeyClassPrivate as String)!:
                keyType = " PRIVATE "
                
            default:
                break
            }
        }
        
        let pem = "-----BEGIN" + keyType + "KEY-----\n" +
            data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
            "\n-----END" + keyType + "KEY-----"
        
        return pem
    }
    
    // MARK: - Creation from Sources
    
    /**
     Creates `SecKey` from data.
     
     - parameter data: The data used to create the key.
     - parameter isPublicKey: A Boolean value indicating the key is public or private.
     
     - returns: The `SecKey` object or nil if data is incorrect.
     */
    static public func make(from data: Data, isPublicKey: Bool) -> SecKey? {
    
        let query = [
            (kSecClass as String): kSecClassKey,
            (kSecAttrApplicationTag as String): UUID().uuidString,
            (kSecAttrKeyType as String): kSecAttrKeyTypeRSA,
            (kSecAttrKeyClass as String): isPublicKey ? kSecAttrKeyClassPublic: kSecAttrKeyClassPrivate,
            (kSecValueData as String): data,
            (kSecReturnRef as String): true
            ]  as CFDictionary
        
        var secKey: AnyObject?
        var status: OSStatus
            
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemAdd(query, &secKey)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        return secKey as! SecKey?
    }
    
    /**
     Creates `SecKey` from PEM text.
     
     - parameter pem: The string in PEM format.
     - parameter isPublicKey: A Boolean value indicating the key is public or private.
     
     - returns: The `SecKey` object or nil if PEM text is incorrect.
     
     - seealso: [PEM Format Description](http://how2ssl.com/articles/working_with_pem_files/)
     */
    static public func make(fromPEM pem: String, isPublicKey: Bool) -> SecKey? {
        
        let base64String = pem.components(separatedBy: "\n")
            .filter {!$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END")}
            .joined(separator: "")
        
        var data = Data(base64Encoded: base64String, options: .ignoreUnknownCharacters) ?? Data()
        
        guard !data.isEmpty else {
            return nil
        }
        
        // Remove header (generated by OpenSSL and other) if needed
        if isPublicKey {

            /*
             SEQUENCE (0x30 + length)
               SEQUENCE (0x30 + length)
                 OBJECT IDENTIFIER 1.2.840.113549.1.1.1 (0x06 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01)
                 NULL (0x05 0x00)

               BIT STRING (0x03 + length)
                 SEPARATOR (0x00)

                 // Public key (what we need)
                 SEQUENCE
                   INTEGER (modulus)
                   INTEGER (exponent)
             */
            let dataBytes = [UInt8](data)
            var offset = 0
            
            let objectIdentifer: [UInt8] = [0x30, 0x0d] +
                [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] +
                [0x05, 0x00]
            
            // Main sequence
            if dataBytes[offset] == 0x30 {
                offset += 1
                
                // Main sequence length
                offset += (dataBytes[offset] > 0x80 ? Int(dataBytes[offset]) - 0x80 + 1 : 1)
                
                // Object identifier sequence
                if [UInt8](dataBytes[offset..<offset + objectIdentifer.count]) == objectIdentifer {
                    offset += objectIdentifer.count
                    
                    // Bit string
                    if dataBytes[offset] == 0x03 {
                        offset += 1
                        
                        // Bit string length
                        offset += (dataBytes[offset] > 0x80 ? Int(dataBytes[offset]) - 0x80 + 1 : 1)
                        
                        // Separator
                        if dataBytes[offset] == 0x00 {
                            offset += 1
                            
                            // Public key without header
                            data = Data(bytes: dataBytes[offset...dataBytes.count - 1])
                        }
                    }
                }
            }
        }
        
        let query = [
            (kSecClass as String): kSecClassKey,
            (kSecAttrApplicationTag as String): UUID().uuidString,
            (kSecAttrKeyType as String): kSecAttrKeyTypeRSA,
            (kSecAttrKeyClass as String): isPublicKey ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate,
            (kSecValueData as String): data,
            (kSecReturnRef as String): true
        ] as CFDictionary
        
        var secKey: AnyObject?
        var status: OSStatus
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemAdd(query, &secKey)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(code: Int(status)))")
        }
        
        return secKey as! SecKey?
    }
}
