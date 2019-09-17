//
//  ECDSA.swift
//  BitcoinKit
//
//  Created by Alexander Cyon on 2019-09-17.
//  Copyright © 2019 BitcoinKit developers. All rights reserved.
//

import Foundation
#if BitcoinKitXcode
import BitcoinKit.Private
#else
import BitcoinKitPrivate
#endif

public struct ECDSA: SignatureScheme {
    public init() {}
}

public extension ECDSA {
    func sign(_ data: Data, privateKey: PrivateKey) throws -> Data {
        #if BitcoinKitXcode
        return _Crypto.signMessage(data, withPrivateKey: privateKey.data)
        #else
        return try _Crypto.signMessage(data, withPrivateKey: privateKey.data)
        #endif
    }

    func verifySignature(_ signature: Data, message: Data, publicKey: Data) throws -> Bool {
        #if BitcoinKitXcode
        return _Crypto.verifySignature(signature, message: message, publicKey: publicKey)
        #else
        return try _Crypto.verifySignature(signature, message: message, publicKey: publicKey)
        #endif
    }

}
