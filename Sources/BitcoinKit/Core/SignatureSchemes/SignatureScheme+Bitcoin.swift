//
//  SignatureScheme+Bitcoin.swift
//  BitcoinKit
//
//  Created by Alexander Cyon on 2019-09-17.
//  Copyright © 2019 BitcoinKit developers. All rights reserved.
//

import Foundation

public extension SignatureScheme {

    func signTransaction(
        _ tx: Transaction,
        utxoToSign: UnspentTransaction,
        hashType: SighashType,
        privateKey: PrivateKey,
        inputIndex: Int = 0
    ) throws -> Data {

        let sighash: Data = tx.signatureHash(
            for: utxoToSign.output,
            inputIndex: inputIndex,
            hashType: hashType
        )

        return try sign(sighash, privateKey: privateKey)
    }

    func verifySigData(
        for tx: Transaction,
        inputIndex: Int,
        utxo: TransactionOutput,
        sigData: Data,
        pubKeyData: Data
    ) throws -> Bool {
        // Hash type is one byte tacked on to the end of the signature. So the signature shouldn't be empty.
        guard !sigData.isEmpty else {
            throw ScriptMachineError.error("SigData is empty.")
        }
        // Extract hash type from the last byte of the signature.
        let hashType = SighashType(sigData.last!)
        // Strip that last byte to have a pure signature.
        let signature = sigData.dropLast()

        let sighash: Data = tx.signatureHash(for: utxo, inputIndex: inputIndex, hashType: hashType)

        return try verifySignature(signature, message: sighash, publicKey: pubKeyData)
    }
}
