//
//  RSAError.swift
//  RSA
//
//  Created by Valery Bashkatov on 13/12/2016.
//  Copyright © 2016 Valery Bashkatov. All rights reserved.
//

import Foundation

/**
 The `RSAError` represents `RSA`'s errors.
 */
public struct RSAError: Error, CustomStringConvertible {
    
    // MARK: - Properties
    
    /// The error codes descriptions.
    private static let descriptions = [
        errSecUnimplemented: "The function or operation is not implemented",
        errSecParam: "One or more parameters passed to a function were not valid",
        errSecAllocate: "Failed to allocate memory",
        errSecNotAvailable: "No keychain is available",
        errSecDuplicateItem: "An item with the same primary key attributes already exists",
        errSecItemNotFound: "The item cannot be found",
        errSecInteractionNotAllowed: "Interaction with the Security Server is not allowed",
        errSecDecode: "Unable to decode the provided data",
        /*errSecMissingEntitlement*/ -34018: "Internal error when a required entitlement isn't present. Keychain entitlement required",
        /*Custom error code*/ 10: "Invalid digest algorithm. Available values: PKCS1SHA1, PKCS1SHA224, PKCS1SHA256, PKCS1SHA384 or PKCS1SHA512"
    ]
    
    /// The error code.
    public let code: OSStatus
    
    /// The description.
    public var description: String {
        return RSAError.descriptions[code] ?? "Unknown error (\(code))"
    }
    
    // MARK: - Initialization
    
    /**
     Initializes `RSAError` instance.
     
     - parameter code: A system code of an error.
     
     - returns: An `RSAError`.
     */
    init(code: OSStatus) {
        self.code = code
    }
}
