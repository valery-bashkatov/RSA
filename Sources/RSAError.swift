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
public enum RSAError: Int, Error, CustomStringConvertible {
    
    /// The function or operation is not implemented.
    case unimplementedFunction = -4
    
    /// One or more parameters passed to a function were not valid.
    case invalidParameter = -50
    
    /// Failed to allocate memory.
    case memoryAllocationFailed = -108
    
    /// No keychain is available.
    case keychainUnavailable = -25291
    
    /// Authorization or authentication failed.
    case authFailed = -25293
    
    /// An item with the same primary key attributes already exists.
    case duplicateKey = -25299
    
    /// The item cannot be found.
    case keyNotFound = -25300
    
    /// Interaction with the user is required in order to grant access or process a request; however, user interaction with the Security Server has been disabled by the program.
    case interactionNotAllowed = -25308
    
    /// Unable to decode the provided data.
    case dataDecodeError = -26275
    
    /// Internal error when a required entitlement isn't present. Keychain entitlement required.
    case missingEntitlement = -34018

    /// Unknown error.
    case unknown = 0

    /// Invalid digest. Available values: PKCS1SHA1, PKCS1SHA224, PKCS1SHA256, PKCS1SHA384 or PKCS1SHA512.
    case invalidDigest = 10
    
    /// Text description of the error.
    public var description: String {
        let text: String
        
        switch self {
        case .unimplementedFunction: text = "The function or operation is not implemented."
        case .invalidParameter: text = "One or more parameters passed to a function were not valid."
        case .memoryAllocationFailed: text = "Failed to allocate memory."
        case .keychainUnavailable: text = "No keychain is available."
        case .authFailed: text = "Authorization or authentication failed."
        case .duplicateKey: text = "An item with the same primary key attributes already exists."
        case .keyNotFound: text = "The item cannot be found."
        case .interactionNotAllowed: text = "Interaction with the user is required in order to grant access or process a request; however, user interaction with the Security Server has been disabled by the program."
        case .dataDecodeError: text = "Unable to decode the provided data."
        case .missingEntitlement: text = "Internal error when a required entitlement isn't present. Keychain entitlement required."
        case .unknown: text = "Unknown error."
        case .invalidDigest: text = "Invalid digest. Available values: PKCS1SHA1, PKCS1SHA224, PKCS1SHA256, PKCS1SHA384 or PKCS1SHA512."
        }
        
        return "RSAError (\(self.rawValue)): \(text)"
    }
}
