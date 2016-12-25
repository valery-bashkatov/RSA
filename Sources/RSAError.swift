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
    
    /// The error code.
    public let code: Int
    
    /// The localized description.
    public var localizedDescription: String {
        let descriptions = [
            -4: "The function or operation is not implemented",
            -50: "One or more parameters passed to a function were not valid",
            -108: "Failed to allocate memory",
            -25291: "No keychain is available",
            -25299: "An item with the same primary key attributes already exists",
            -25300: "The item cannot be found",
            -25308: "Interaction with the user is required in order to grant access or process a request; however, user interaction with the Security Server has been disabled by the program",
            -26275: "Unable to decode the provided data",
            -34018: "Internal error when a required entitlement isn't present. Keychain entitlement required",
            10: "Invalid digest algorithm. Available values: PKCS1SHA1, PKCS1SHA224, PKCS1SHA256, PKCS1SHA384 or PKCS1SHA512"
        ]
        
        return descriptions[code] ?? "Unknown error (\(code))"
    }
    
    /// The description.
    public var description: String {
        return localizedDescription
    }
    
    // MARK: - Initialization
    
    /**
     Initializes `RSAError` instance.
     
     - parameter code: A system code of an error.
     
     - returns: An `RSAError`.
     */
    init(code: Int) {
        self.code = code
    }
}
