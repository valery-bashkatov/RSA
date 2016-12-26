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
    static private let descriptions = [
        Int(errSecUnimplemented): "The function or operation is not implemented",
        Int(errSecParam): "One or more parameters passed to a function were not valid",
        Int(errSecAllocate): "Failed to allocate memory",
        Int(errSecNotAvailable): "No keychain is available",
        Int(errSecDuplicateItem): "An item with the same primary key attributes already exists",
        Int(errSecItemNotFound): "The item cannot be found",
        Int(errSecInteractionNotAllowed): "Interaction with the Security Server is not allowed",
        Int(errSecDecode): "Unable to decode the provided data",
        /* errSecMissingEntitlement */ -34018: "Internal error when a required entitlement isn't present. Keychain entitlement required",
        /* custom */ 10: "Invalid digest algorithm. Available values: PKCS1SHA1, PKCS1SHA224, PKCS1SHA256, PKCS1SHA384 or PKCS1SHA512"
    ]
    
    /// The error code.
    public let code: Int
    
    /// The description.
    public var description: String {
        return RSAError.descriptions[code] ?? "Unknown error (\(code))"
    }
}
