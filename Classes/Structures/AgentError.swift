//
//  Principal.swift
//  AgentSwift
//
//  Created by Alex on 2022/8/23.
//

open class AgentError: Error {
    final let error: String
    
    init(_ error: String) {
        self.error = error
    }
    
    public var description: String { return error }
}

class AgentArgumentError: AgentError {
    final let invalidValue: Any?
    final let hasValue: Bool
    final let message: String?
    final let name: String?
    
    init(_ message: String?, _ name: String?) {
        self.message = message
        self.name = name
        self.invalidValue = nil
        self.hasValue = false
        super.init("")
    }
    
    init(value: Any?, name: String?, message: String?) {
        self.invalidValue = value
        self.hasValue = true
        self.name = name
        self.message = message
        super.init("")
    }
    
    override public var description: String {
        let nameString = name == nil ? "" : " \(String(describing: name))"
        let messageString = message == nil ? "" : ": \(String(describing: message))"
        let errorName = "Invalid argument\(hasValue ? "" : "(s)")"
        let prefix = "\(errorName)\(nameString)\(messageString)"
        if (hasValue) {
            return "\(prefix): \(String(describing: invalidValue))"
        }
        return prefix
    }
}
