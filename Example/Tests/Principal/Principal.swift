//
//  Principal.swift
//  AgentSwift_Tests
//
//  Created by Alex on 2022/10/5.
//  Copyright © 2022 CocoaPods. All rights reserved.
//

import XCTest
import AgentSwift

class PrincipalTests: XCTestCase {
    override func setUp() {
        super.setUp()
    }
    
    override func tearDown() {
        super.tearDown()
    }
    
    func test() {
        let principal = try! Principal.fromText("2chl6-4hpzw-vqaaa-aaaaa-c")
        XCTAssert(true, "Pass")
    }
}
