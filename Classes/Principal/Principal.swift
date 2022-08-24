//
//  Principal.swift
//  AgentSwift
//
//  Created by Alex on 2022/8/23.
//

import Foundation
import CryptoSwift
import SwiftBase32

let kSuffixSelfAuthenticating = UInt8(2)
let kSuffixAnonymous = UInt8(4)

public class Principal: Equatable {
    let array : [UInt8]
    
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
        return Principal(fromHexString(hex))
    }
    
    static public func fromText(_ text: String) throws -> Principal {
        let canisterIdNoDash = text.lowercased().replacingOccurrences(
            of: "-",
            with: ""
        )
        let array = base32Decode(canisterIdNoDash)!
        let slicedArray = Array(array[1...array.count - 4])
        let principal = Principal(slicedArray)
        let newText = principal.toText()
        if (newText != text) {
            throw AgentError("Principal \(newText) does not have a valid checksum.")
        }
        return principal
    }
    
    public var isAnonymous: Bool {
        return array.count == 1 && array[0] == kSuffixAnonymous
    }
    
    public func toUint8Array() -> [UInt8] {
        return array
    }
    
    public func toHex() -> String {
        return toHexString(array).uppercased()
    }
    
    public func toText() -> String {
        var checksumArrayBuffer = Data([UInt8](repeating: UInt8(0), count: 4))
        checksumArrayBuffer[0] = UInt8(checksumArrayBuffer.bytes.crc32())
        let checksum = checksumArrayBuffer.bytes
        let array = checksum + self.array
        let result = base32Encode(array)
        let range = NSRange(location: 0, length: result.utf16.count)
        let reg = try! NSRegularExpression(pattern: ".{1,5}")
        let matches = reg.matches(in: result, options: [], range: range)
        return matches.map{ "\($0)" }.joined(separator: "-")
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

func fromHexString(_ hexString: String) -> [UInt8] {
    let range = NSRange(location: 0, length: hexString.utf16.count)
    let reg = try! NSRegularExpression(pattern: ".{1,2}")
    let matches = reg.matches(in: hexString, options: [], range: range)
    let list = matches.map{ UInt8(Int("\($0)", radix: 16)!) }
    return list
}

func toHexString(_ bytes: [UInt8]) -> String {
    return bytes.reduce("") {
        $0 + String($1, radix: 16).padding(toLength: 2, withPad: "0", startingAt: 0)
    }
}
