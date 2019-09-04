//
//  Mnemonic.swift
//
//  Copyright © 2018 Kishikawa Katsumi
//  Copyright © 2018 BitcoinKit developers
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

import Foundation
#if BitcoinKitXcode
import BitcoinKit.Private
#else
import BitcoinKitPrivate
#endif

private let bitsPerByte = 8
private let wordListSizeLog2 = 11 // 2^11 => 2048

public struct Mnemonic {

    public enum Strength: Int, CaseIterable {
        case `default` = 128
        case low = 160
        case medium = 192
        case high = 224
        case veryHigh = 256

        init?(wordCount: Int) {
            guard
                let entropyInBitsFromWordCount = Strength.entropyInBitsFrom(wordCount: wordCount),
                let strength = Strength(rawValue: entropyInBitsFromWordCount)
            else { return nil }
            self = strength
        }

        fileprivate var wordCount: WordCount {
            let wordCountInt = Strength.wordCountFrom(entropyInBits: rawValue)
            guard let wordCount = WordCount(rawValue: wordCountInt) else {
                fatalError("Missed to include word count: \(wordCountInt)")
            }
            return wordCount
        }

        fileprivate static func wordCountFrom(entropyInBits: Int) -> Int {
            return Int(ceil(Double(entropyInBits) / Double(wordListSizeLog2)))
        }

        /// `wordCount` must be divisible by `3`, else `nil` is returned
        fileprivate static func entropyInBitsFrom(wordCount: Int) -> Int? {
            guard wordCount % Strength.checksumBitsPerWord == 0 else { return nil }
            return (wordCount / Strength.checksumBitsPerWord) * 32
        }

        fileprivate static let checksumBitsPerWord = 3
        fileprivate var checksumLength: Int {
            return wordCount.wordCount / Strength.checksumBitsPerWord
        }

        // swiftlint:disable:next nesting
        fileprivate enum WordCount: Int {
            case wordCountOf12 = 12
            case wordCountOf15 = 15
            case wordCountOf18 = 18
            case wordCountOf21 = 21
            case wordCountOf24 = 24

            public var wordCount: Int {
                return rawValue
            }
        }
    }

    public enum Language: String, CaseIterable {
        case english
        case japanese
        case korean
        case spanish
        case simplifiedChinese
        case traditionalChinese
        case french
        case italian
    }

    public static func generate(strength: Strength = .default, language: Language = .english) throws -> [String] {
        let byteCount = strength.rawValue / bitsPerByte
        var bytes = Data(count: byteCount)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, byteCount, $0) }
        guard status == errSecSuccess else { throw MnemonicError.randomBytesError }
        return try generate(entropy: bytes, language: language)
    }

    public static func deriveLanguageFromMnemonic(words: [String]) -> Language? {
        func tryLangauge(
            _ language: Language
        ) -> Language? {
            let vocabulary = Set(wordList(for: language))
            let wordsLeftToCheck = Set(words)

            guard wordsLeftToCheck.intersection(vocabulary) == wordsLeftToCheck else {
                return nil
            }

            return language
        }

        for langauge in Language.allCases {
            guard let derived = tryLangauge(langauge) else { continue }
            return derived
        }
        return nil
    }

    @discardableResult
    public static func validateChecksumDerivingLanguageOf(mnemonic mnemonicWords: [String]) throws -> Bool {
        guard let derivedLanguage = deriveLanguageFromMnemonic(words: mnemonicWords) else {
            throw MnemonicError.invalid(.unableToDeriveLanguageFrom(words: mnemonicWords))
        }
        return try validateChecksumOf(mnemonic: mnemonicWords, language: derivedLanguage)
    }

    // https://github.com/mcdallas/cryptotools/blob/master/btctools/HD/__init__.py#L27-L41
    // alternative in C:
    // https://github.com/trezor/trezor-crypto/blob/0c622d62e1f1e052c2292d39093222ce358ca7b0/bip39.c#L161-L179
    @discardableResult
    public static func validateChecksumOf(mnemonic mnemonicWords: [String], language: Language) throws -> Bool {
        let vocabulary = wordList(for: language)

        let indices: [UInt11] = try mnemonicWords.map { word in
            guard let indexInVocabulary = vocabulary.firstIndex(of: word) else {
                throw MnemonicError.invalid(.wordNotInList(word, language: language))
            }
            guard let indexAs11Bits = UInt11(exactly: indexInVocabulary) else {
                fatalError("Unexpected error, is word list longer than 2048 words, it shold not be")
            }
            return indexAs11Bits
        }

        let bitArray = BitArray(indices)

        let checksumLength = mnemonicWords.count / 3

        let dataBits = bitArray.prefix(subtractFromCount: checksumLength)
        let checksumBits = bitArray.suffix(maxBitCount: checksumLength)

        let hash = Crypto.sha256(dataBits.asData())

        let hashBits = BitArray(data: hash).prefix(maxBitCount: checksumLength)

        guard hashBits == checksumBits else {
            throw MnemonicError.invalid(.checksumMismatch)
        }

        // All is well
        return true
    }

    private static func intToBinString<I>(_ int: I) -> String where I: BinaryInteger {
        guard let uint8 = UInt8(exactly: int) else { fatalError("could not create uint8 from integer: \(int)") }
        return byteToBinString(byte: uint8)
    }

    private static func byteToBinString(byte: UInt8) -> String {
        return String(("00000000" + String(byte, radix: 2)).suffix(8))
      }

    internal static func generate(
        entropy: Data,
        language: Language = .english
    ) throws -> [String] {

        let entropybits = String(entropy.flatMap { ("00000000" + String($0, radix: 2)).suffix(bitsPerByte) })
        let hash = Crypto.sha256(entropy)
        let hashBits = String(hash.flatMap { ("00000000" + String($0, radix: 2)).suffix(bitsPerByte) })
        let checkSum = String(hashBits.prefix((entropy.count * bitsPerByte) / 32))

        let words = wordList(for: language)
        let concatenatedBits = entropybits + checkSum

        var mnemonic: [String] = []
        for index in 0..<(concatenatedBits.count / wordListSizeLog2) {
            let startIndex = concatenatedBits.index(concatenatedBits.startIndex, offsetBy: index * wordListSizeLog2)
            let endIndex = concatenatedBits.index(startIndex, offsetBy: wordListSizeLog2)
            let wordIndex = Int(strtoul(String(concatenatedBits[startIndex..<endIndex]), nil, 2))
            mnemonic.append(String(words[wordIndex]))
        }

        try validateChecksumOf(mnemonic: mnemonic, language: language)

        return mnemonic
    }

    /// Pass a trivial closure: `{ _ in }` to `validateChecksum` if you would like to opt-out of checksum validation.
    public static func seed(
        mnemonic words: [String],
        passphrase: String = "",
        validateChecksum: (([String]) throws -> Void) = { try Mnemonic.validateChecksumDerivingLanguageOf(mnemonic: $0) }
    ) rethrows -> Data {

        try validateChecksum(words)

        let mnemonic = words.joined(separator: " ").decomposedStringWithCompatibilityMapping.data(using: .utf8)!
        let salt = ("mnemonic" + passphrase).decomposedStringWithCompatibilityMapping.data(using: .utf8)!
        let seed = _Key.deriveKey(mnemonic, salt: salt, iterations: 2048, keyLength: 64)
        return seed
    }

    public static func wordList(for language: Language) -> [String] {
        switch language {
        case .english:
            return WordList.english
        case .japanese:
            return WordList.japanese
        case .korean:
            return WordList.korean
        case .spanish:
            return WordList.spanish
        case .simplifiedChinese:
            return WordList.simplifiedChinese
        case .traditionalChinese:
            return WordList.traditionalChinese
        case .french:
            return WordList.french
        case .italian:
            return WordList.italian
        }
    }
}

public enum MnemonicError: Error {
    case randomBytesError

    indirect case invalid(MnemonicValidationError)
    public enum MnemonicValidationError: Error {
        case badWordCount(expectedAnyOf: [Int], butGot: Int)
        case wordNotInList(String, language: Mnemonic.Language)
        case unableToDeriveLanguageFrom(words: [String])
        case checksumMismatch
    }
}
