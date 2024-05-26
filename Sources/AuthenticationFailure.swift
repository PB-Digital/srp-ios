//
//  AuthenticationFailure.swift
//  srp-sample
//
//  Created by Karim Karimov on 26.05.24.
//

import Foundation

/// Possible authentication failure modes.
public enum AuthenticationFailure: Error {
    /// Security breach: the provided public key is empty (i.e. PK % N is zero).
    case invalidPublicKey
}

extension AuthenticationFailure: CustomStringConvertible {
    /// A textual representation of this instance.
    ///
    /// Instead of accessing this property directly, convert an instance of any
    /// type to a string by using the `String(describing:)` initializer.
    public var description: String {
        switch self {
        case .invalidPublicKey: return "security breach - the provided public key is invalid"
        }
    }
}
