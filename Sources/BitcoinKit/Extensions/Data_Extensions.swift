//
//  Data_Extensions.swift
//  BitcoinKit
//
//  Created by Alexander Cyon on 2019-09-04.
//  Copyright © 2019 BitcoinKit developers. All rights reserved.
//

import Foundation

extension Data {
    var binaryString: String {
        var result: [String] = []
        for byte in self {
            let byteString = String(byte, radix: 2)
            let padding = String(repeating: "0",
                                 count: 8 - byteString.count)
            result.append(padding + byteString)
        }
        return result.joined()
    }
}
