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
    public var attributes: [String: Any] {
        
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
        
        return attributes as! [String: Any]
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
     The key in PEM format. Public key's PEM will also contain header data required for OpenSSL and other applications, but not in the internal iOS representation of the key.
     */
    public var pem: String {
        var data = self.data
        var isPublicKey = true
        
        if let keyClass = attributes[kSecAttrKeyClass as String] as? Int {
            
            switch keyClass {
            case Int(kSecAttrKeyClassPublic as String)!:
                isPublicKey = true
                
            case Int(kSecAttrKeyClassPrivate as String)!:
                isPublicKey = false
                
            default:
                break
            }
        }
        
        if isPublicKey {
            
            /*
             // Header (we need to generate it)
             SEQUENCE (0x30 + length)
               SEQUENCE (0x30 + length (0x0d))
                 OBJECT IDENTIFIER 1.2.840.113549.1.1.1 (0x06 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01)
                 NULL (0x05 0x00)
             
               BIT STRING (0x03 + length)
                 SEPARATOR (0x00)
             
                 // Public key (initial data contains only this)
                 SEQUENCE
                   INTEGER (modulus)
                   INTEGER (exponent)
             */
            
            let objectIdentifer: [UInt8] = [0x30, 0x0d] +
                [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] +
                [0x05, 0x00]
            
            var header = Data()
            
            let encodeLength = {
                (length: Int) -> [UInt8] in
                
                var length = length
                
                guard length > 0 else {
                    return []
                }
                
                var bytes = [UInt8]()
                var bytesCount = 1
                
                while (bytesCount < 8 && length >= (1 << (bytesCount * 8))) {
                    bytesCount += 1
                }
                
                if length < 0x80 {
                    bytes.append(UInt8(length))
                    
                } else {
                    for _ in 0..<bytesCount {
                        bytes.append(UInt8(length & 0xff))
                        length = length >> 8
                    }
                    
                    bytes = [UInt8(0x80 + bytesCount)] + bytes.reversed()
                }
                
                return bytes
            }
            
            // Construct header in reverse order
            
            // Separator
            header.insert(0x00, at: 0)
            
            // Bit string
            header.insert(contentsOf: encodeLength(header.count + data.count), at: 0)
            header.insert(0x03, at: 0)
            
            // Object identifier sequence
            header.insert(contentsOf: objectIdentifer, at: 0)
            
            // Main sequence
            header.insert(contentsOf: encodeLength(header.count + data.count), at: 0)
            header.insert(0x30, at: 0)
            
            // Header + initial data (public key)
            data = header + data
        }
        
        let pem = "-----BEGIN " + (isPublicKey ? "PUBLIC" : "PRIVATE") + " KEY-----\n" +
            data.base64EncodedString(options: [.lineLength64Characters, .endLineWithLineFeed]) +
            "\n-----END " + (isPublicKey ? "PUBLIC" : "PRIVATE") + " KEY-----"
        
        return pem
    }
    
    // MARK: - Creation from Sources
    
    /**
     Creates `SecKey` from data.
     
     - parameter data: The data used to create the key.
     - parameter isPublicKey: A Boolean value indicating the key is public or private.
     
     - throws: An `RSAError` if an error occurs.
     
     - returns: The `SecKey` object or nil if data is incorrect.
     */
    static public func make(from data: Data, isPublicKey: Bool) throws -> SecKey {
    
        guard !data.isEmpty else {
            throw RSAError(code: 20)
        }
        
        if #available(iOS 10.0, *) {
            
            let query = [
                (kSecAttrKeyType as String): kSecAttrKeyTypeRSA,
                (kSecAttrKeyClass as String): isPublicKey ? kSecAttrKeyClassPublic: kSecAttrKeyClassPrivate
            ] as CFDictionary
            
            var error: Unmanaged<CFError>?
            guard let secKey = SecKeyCreateWithData(data as CFData, query, &error) else {
                throw RSAError(code: 20)
            }
            
            return secKey

        } else {
            
            let query = [
                (kSecClass as String): kSecClassKey,
                (kSecAttrApplicationTag as String): UUID().uuidString,
                (kSecAttrKeyType as String): kSecAttrKeyTypeRSA,
                (kSecAttrKeyClass as String): isPublicKey ? kSecAttrKeyClassPublic: kSecAttrKeyClassPrivate,
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
            
            guard (secKey as! SecKey?) != nil else {
                throw RSAError(code: 20)
            }
            
            return secKey as! SecKey
        }
    }
    
    /**
     Creates `SecKey` from PEM text. The method also trims header data (generated by OpenSSL and others) from PEM if needed.
     
     - parameter pem: The string in PEM format.
     - parameter isPublicKey: A Boolean value indicating the key is public or private.
     
     - throws: An `RSAError` if an error occurs.
     
     - returns: The `SecKey` object or nil if PEM text is incorrect.
     */
    static public func make(fromPEM pem: String, isPublicKey: Bool) throws -> SecKey {
        
        let base64String = pem.components(separatedBy: "\n")
            .filter {!$0.hasPrefix("-----BEGIN") && !$0.hasPrefix("-----END")}
            .joined(separator: "")
        
        var data = Data(base64Encoded: base64String, options: .ignoreUnknownCharacters) ?? Data()
        
        guard !data.isEmpty else {
            throw RSAError(code: 20)
        }
        
        // Remove header (generated by OpenSSL and other) if needed
        if isPublicKey {

            /*
             // Header (need to remove)
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
            throw RSAError(code: Int(status))
        }
        
        status = SecItemAdd(query, &secKey)
        guard status == errSecSuccess else {
            throw RSAError(code: Int(status))
        }
        
        status = SecItemDelete(query)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw RSAError(code: Int(status))
        }
        
        guard (secKey as! SecKey?) != nil else {
            throw RSAError(code: 20)
        }
        
        return secKey as! SecKey
    }
}
