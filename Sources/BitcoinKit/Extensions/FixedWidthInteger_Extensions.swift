//
//  FixedWidthInteger_Extensions.swift
//  BitcoinKit
//
//  Created by Alexander Cyon on 2019-09-04.
//  Copyright © 2019 BitcoinKit developers. All rights reserved.
//

import Foundation

extension FixedWidthInteger {
    var binaryString: String {
        var result: [String] = []
        for i in 0..<(Self.bitWidth / 8) {
            let byte = UInt8(truncatingIfNeeded: self >> (i * 8))
            let byteString = String(byte, radix: 2)
            let padding = String(repeating: "0",
                                 count: 8 - byteString.count)
            result.append(padding + byteString)
        }
        return result.reversed().joined()
    }
}
