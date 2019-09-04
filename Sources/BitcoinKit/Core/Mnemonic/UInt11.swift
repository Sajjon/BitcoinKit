//
//  UInt11.swift
//  BitcoinKit
//
//  Created by Alexander Cyon on 2019-09-04.
//  Copyright © 2019 BitcoinKit developers. All rights reserved.
//

import Foundation

struct UInt11: ExpressibleByIntegerLiteral {
    static var bitWidth: Int { 11 }

    static var max16: UInt16 { UInt16(2047) }
    static var max: UInt11 { UInt11(exactly: max16)! }

    static var min: UInt11 { 0 }

    private let valueBoundBy16Bits: UInt16

    init?<T>(exactly source: T) where T: BinaryInteger {
        guard
            let valueBoundBy16Bits = UInt16(exactly: source),
            valueBoundBy16Bits < 2048 else { return nil }

        self.valueBoundBy16Bits = valueBoundBy16Bits
    }

}

extension UInt11 {
    init<T>(truncatingIfNeeded source: T) where T: BinaryInteger {
         let valueBoundBy16Bits = UInt16(truncatingIfNeeded: source)
         self.valueBoundBy16Bits = Swift.min(UInt11.max16, valueBoundBy16Bits)
     }

     /// Creates a new integer value from the given string and radix.
     init?<S>(_ text: S, radix: Int = 10) where S: StringProtocol {
         guard let uint16 = UInt16(text, radix: radix) else { return nil }
         self.init(exactly: uint16)
     }

    init(integerLiteral value: Int) {
        guard let exactly = UInt11(exactly: value) else {
            fatalError("bad integer literal value does not fit in UInt11, value passed was: \(value)")
        }
        self = exactly
    }
}

extension UInt11 {
    var binaryString: String {
        let binaryString = String(valueBoundBy16Bits.binaryString.suffix(Self.bitWidth))
        assert(UInt16(binaryString, radix: 2)! == valueBoundBy16Bits, "incorrect conversion.")
        return binaryString
    }
}
