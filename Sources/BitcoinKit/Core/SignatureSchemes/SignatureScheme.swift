//
//  SignatureScheme.swift
//  BitcoinKit
//
//  Created by Alexander Cyon on 2019-09-17.
//  Copyright © 2019 BitcoinKit developers. All rights reserved.
//

import Foundation

public protocol SignatureScheme {
    func sign(_ data: Data, privateKey: PrivateKey) throws -> Data
    func verifySignature(_ signature: Data, message: Data, publicKey: Data) throws -> Bool
}
