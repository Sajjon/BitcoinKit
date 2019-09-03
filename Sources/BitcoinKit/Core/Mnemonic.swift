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
            return Int(ceil(Double(entropyInBits) / Double(11)))
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
        let byteCount = strength.rawValue / 8
        var bytes = Data(count: byteCount)
        let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, byteCount, $0) }
        guard status == errSecSuccess else { throw MnemonicError.randomBytesError }
        return generate(entropy: bytes, language: language)
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

    public static func validateChecksumDerivingLanguageOf(mnemonic mnemonicWords: [String]) throws {
        guard let derivedLanguage = deriveLanguageFromMnemonic(words: mnemonicWords) else {
            throw MnemonicError.invalid(.unableToDeriveLanguageFrom(words: mnemonicWords))
        }
        try validateChecksumOf(mnemonic: mnemonicWords, language: derivedLanguage)
    }

    // https://github.com/mcdallas/cryptotools/blob/master/btctools/HD/__init__.py#L27-L41
    // alternative in C:
    // https://github.com/trezor/trezor-crypto/blob/0c622d62e1f1e052c2292d39093222ce358ca7b0/bip39.c#L161-L179
    public static func validateChecksumOf(mnemonic mnemonicWords: [String], language: Language) throws {
        let allowedWordCounts = Strength.allCases.map({ $0.wordCount.wordCount })
        let wordCount = mnemonicWords.count
        guard allowedWordCounts.contains(wordCount) else {
            throw MnemonicError.invalid(.badWordCount(expectedAnyOf: allowedWordCounts, butGot: wordCount))
        }
        let list = wordList(for: language)
        let wordlist = wordList(for: language)
        let indexes: [Int] = try mnemonicWords.map { (word: String) throws -> Int in
            guard let index = wordlist.firstIndex(of: word) else {
                throw MnemonicError.invalid(.wordNotInList(word, language: language))
            }
            return index
        }
        let binaryString: String = indexes.map { String($0, radix: 2).prepending(character: "0", toLength: 11) }.joined()

        let checksumLength = wordCount / 3 /* in python the double division operator `//` is used, which is divideAndFloor */
        guard checksumLength <= 8 else { fatalError("wordCount of: \(wordCount) not supported") }

        func extractRelevantData(usePrefix usePrefixElseUseSuffix: Bool, numberOfBits n: Int) -> UInt8 {
            let s = binaryString
            let subString = usePrefixElseUseSuffix ? s.prefix(n) : s.suffix(n)

            guard let byteFromSubstring = UInt8(String(subString), radix: 2) else {
                fatalError("failed to extract relevant data")
            }
            return byteFromSubstring
        }

        let expectedChecksum: UInt8 = extractRelevantData(usePrefix: false, numberOfBits: checksumLength)
        func dataFromBinaryString(_ partialBinaryString: String) -> Data {
            var partialBinaryString = partialBinaryString
            let bitsPerByte = 8
            var bytes = [UInt8]()
            while !partialBinaryString.isEmpty {
                let byteAsString = String(partialBinaryString.prefix(bitsPerByte)).prepending(character: "0", toLength: bitsPerByte)
                guard let byte = UInt8(byteAsString, radix: 2) else {
                    print("failed to create byte from string: \(byteAsString)")
                    fatalError("failed to create byte from string: \(byteAsString)")
                }
                bytes.append(byte)
                partialBinaryString = String(partialBinaryString.dropFirst(bitsPerByte))
            }
            return Data(bytes)
        }
        let data = dataFromBinaryString(String(binaryString.prefix(binaryString.count - checksumLength)))

        let hash = Crypto.sha256(data)
        let checksumFromHashWholeByte: UInt8 = hash[0]

        guard
            case let relevantBits = String(checksumFromHashWholeByte, radix: 2).prefix(checksumLength),
            let checksumFromHashOnlyRelevantBits = UInt8(relevantBits, radix: 2) else {
            fatalError("should work to get relevant bits from checksum and fit in a single byte (assuming a max entropy of 256 bits)")
        }

        guard checksumFromHashOnlyRelevantBits == expectedChecksum else {
            throw MnemonicError.invalid(.checksumMismatch)
        }

        // All is well
    }

    private static func intToBinString<I>(_ int: I) -> String where I: BinaryInteger {
        guard let uint8 = UInt8(exactly: int) else { fatalError("could not create uint8 from integer: \(int)") }
        return byteToBinString(byte: uint8)
    }

    private static func byteToBinString(byte: UInt8) -> String {
        return String(("00000000" + String(byte, radix: 2)).suffix(8))
      }

    internal static func generate(entropy: Data, language: Language = .english) -> [String] {
        let list = wordList(for: language)
        var binaryString = entropy.map { byteToBinString(byte: $0) }.joined()

        let hash = Crypto.sha256(entropy)
        let bits = entropy.count * 8
        let cs = bits / 32

        let hashbits = hash.map { byteToBinString(byte: $0) }.joined()
        let checksum = String(hashbits.prefix(cs))
        binaryString += checksum

        var mnemonic = [String]()
        let wordCount = Mnemonic.Strength.wordCountFrom(entropyInBits: binaryString.count)

        for nextWordIndex in 0..<wordCount {
            let rangeStart = binaryString.index(binaryString.startIndex, offsetBy: nextWordIndex * 11)
            let rangeEnd = binaryString.index(binaryString.startIndex, offsetBy: (nextWordIndex + 1) * 11)
            let range = rangeStart..<rangeEnd
            let bitsInRange = binaryString[range]
            let wordIndex = Int(bitsInRange, radix: 2)!

            let mnemonicWord = list[wordIndex]
            mnemonic.append(mnemonicWord)
        }
        return mnemonic
    }

    public static func seed(mnemonic words: [String], passphrase: String = "") throws -> Data {
//        try validateChecksumDerivingLanguageOf(mnemonic: words)
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

private extension BinaryInteger {
    var asData: Data {
        var int = self
        return Data(bytes: &int, count: MemoryLayout<Self>.size)
    }
}

enum ConcatMode {
    case prepend
    case append
}

extension String {
    func append(character: Character, toLength expectedLength: Int?) -> String {
        return prependingOrAppending(character: character, toLength: expectedLength, mode: .append)
    }

    func prepending(character: Character, toLength expectedLength: Int?) -> String {
        return prependingOrAppending(character: character, toLength: expectedLength, mode: .prepend)
    }

    mutating func prependOrAppend(character: Character, toLength expectedLength: Int?, mode: ConcatMode) {
        self = prependingOrAppending(character: character, toLength: expectedLength, mode: mode)
    }

    func prependingOrAppending(character: Character, toLength expectedLength: Int?, mode: ConcatMode) -> String {
        guard let expectedLength = expectedLength else {
            return self
        }
        var modified = self
        let new = String(character)
        while modified.count < expectedLength {
            switch mode {
            case .prepend: modified = new + modified
            case .append: modified += new
            }

        }
        return modified
    }
}
