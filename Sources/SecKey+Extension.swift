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
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemAdd(query, &attributes)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
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
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemAdd(query, &data)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
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
    public static func make(from data: Data, isPublicKey: Bool) -> SecKey? {
    
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
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemAdd(query, &secKey)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
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
    public static func make(fromPEM pem: String, isPublicKey: Bool) -> SecKey? {
        
        let base64String = pem.components(separatedBy: "\n")
            .filter {!$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END")}
            .joined(separator: "")
        
        let data = Data(base64Encoded: base64String, options: .ignoreUnknownCharacters) ?? Data()
        
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
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemAdd(query, &secKey)
        guard status == errSecSuccess else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            fatalError("\(RSAError(rawValue: Int(status)) ?? RSAError.unknown)")
        }
        
        return secKey as! SecKey?
    }
    
    /*
     
     private static func clearData(data: NSData) -> NSData {
     var dataBytes = [UInt8](count: data.length, repeatedValue: 0)
     
     data.getBytes(&dataBytes, length: data.length)
     
     var index = 0
     guard dataBytes[index] == 0x30 else {
     return data
     }
     
     index += 1
     if dataBytes[index] > 0x80 {
     index += Int(dataBytes[index]) - 0x80 + 1
     }
     else {
     index += 1
     }
     
     if Int(dataBytes[index]) == 0x02 {
     return data
     }
     
     guard Int(dataBytes[index]) == 0x30 else {
     return data
     }
     
     index += 15
     if dataBytes[index] != 0x03 {
     return data
     }
     
     index += 1
     if dataBytes[index] > 0x80 {
     index += Int(dataBytes[index]) - 0x80 + 1
     }
     else {
     index += 1
     }
     
     guard dataBytes[index] == 0 else {
     return data
     }
     
     index += 1
     dataBytes.removeRange(0..<index)
     
     return NSData(bytes: dataBytes, length: dataBytes.count)
     }
     */
}
