//
//  Principal.swift
//  AgentSwift
//
//  Created by Alex on 2022/8/23.
//

import Foundation
import CryptoSwift
import SwiftBase32
import SwiftCBOR

let kSuffixSelfAuthenticating = UInt8(2)
let kSuffixAnonymous = UInt8(4)

public class Principal: CBOREncodable, Equatable {
    private var array : [UInt8]
    
    init(_ array: [UInt8]) {
        self.array = array
    }
    
    static public func anonymous() -> Principal {
        return Principal([kSuffixAnonymous])
    }
    
    static public func selfAuthenticating(_ publicKey: [UInt8]) -> Principal {
        let hash = publicKey.sha224()
        let array = hash + [kSuffixSelfAuthenticating]
        return Principal(array)
    }
    
    static public func from(_ other: Any) throws -> Principal {
        if let str = other as? String {
            return try Principal.fromText(str)
        } else if let map = other as? NSDictionary, let isPrincipal = map["_isPrincipal"] as? Bool, isPrincipal == true, let value = map["_arr"] as? [UInt8] {
            return Principal(value)
        } else if let principal = other as? Principal {
            return Principal(principal.array)
        }
        throw AgentError("Impossible to convert \(String(describing: other)) to Principal.")
    }
    
    static public func fromHex(_ hex: String) -> Principal {
        return Principal(hex.toUInt8List())
    }
    
    static public func fromText(_ text: String) throws -> Principal {
        let canisterIdNoDash = text.lowercased().replacingOccurrences(
            of: "-",
            with: ""
        )
        let array = base32Decode(canisterIdNoDash)!
        let slicedArray = Array(array[4...array.count - 1])
        let principal = Principal(slicedArray)
        let newText = principal.toText()
        if (newText != text) {
            throw AgentError("Principal \(newText) does not have a valid checksum.")
        }
        return principal
    }
    
    public var isAnonymous: Bool {
        return self.array.count == 1 && self.array[0] == kSuffixAnonymous
    }
    
    public func toUint8Array() -> [UInt8] {
        return self.array
    }
    
    // MARK: - Encode Principals to CBOR value.
    public func encode(options: CBOROptions) -> [UInt8] {
        return self.toUint8Array()
    }
    
    public func toHex() -> String {
        return self.array.toHexString().uppercased()
    }
    
    public func toText() -> String {
        var crc = self.array.crc32()
        let checksumArrayBuffer = Data(bytes: &crc, count: MemoryLayout<UInt32>.size)
        let checksum = checksumArrayBuffer.bytes.reversed()
        let array = checksum + self.array
        var encoded = base32Encode(array).lowercased()
        encoded.removeAll(where: { "=".contains($0) })
        let range = NSRange(location: 0, length: encoded.utf16.count)
        let reg = try! NSRegularExpression(pattern: ".{1,5}")
        let matches = reg.matches(in: encoded, options: [], range: range)
        var resultList = [String]()
        for match in matches {
            let str = encoded.substring(with: match.range)!.lowercased()
            resultList.append(str)
        }
        let result = resultList.joined(separator: "-")
        return result
    }
    
    public func toAccountId(subAccount: [UInt8]?) throws -> [UInt8] {
        if (subAccount?.count != 32) {
            throw AgentArgumentError(
                value: subAccount,
                name: "subAccount",
                message: "Length is invalid, must be 32."
            )
        }
        var data = Data([0x0a])
        data += "account-id".utf8
        data += self.toUint8Array()
        data += subAccount ?? [UInt8](repeating: UInt8(0), count: 32)
        data = data.sha224()
        var buffer = Data([UInt8](repeating: UInt8(0), count: 4))
        buffer[0] = UInt8(data.bytes.crc32())
        let checksum = buffer.bytes
        return checksum + data
    }
    
    // MARK: - Compare principals by converting them to HEX strings.
    public static func == (left: Principal, right: Principal) -> Bool {
        return left.toHex() == right.toHex()
    }
    
    public var description: String { return toText() }
}

extension String {
    func toUInt8List() -> [UInt8] {
        let range = NSRange(location: 0, length: self.utf16.count)
        let reg = try! NSRegularExpression(pattern: ".{1,2}")
        let matches = reg.matches(in: self, options: [], range: range)
        let list = matches.map{ UInt8("\($0)", radix: 16)! }
        return list
    }
}

extension Array where Element == UInt8 {
    func toHexString() -> String {
        return self.reduce("") {
            $0 + String($1, radix: 16).padding(toLength: 2, withPad: "0", startingAt: 0)
        }
    }
}

private extension String {
    func substring(with range: NSRange) -> Substring? {
        guard let r = Range(range, in: self) else { return nil }
        return self[r]
    }
}
