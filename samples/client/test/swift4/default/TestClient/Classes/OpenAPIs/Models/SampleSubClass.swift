//
// SampleSubClass.swift
//
// Generated by openapi-generator
// https://openapi-generator.tech
//

import Foundation


/** This is a subclass defived from the SampleBase class. */

public struct SampleSubClass: Codable {

    public var baseClassStringProp: String?
    public var baseClassIntegerProp: Int?
    public var subClassStringProp: String?
    public var subClassIntegerProp: Int?

    public init(baseClassStringProp: String?, baseClassIntegerProp: Int?, subClassStringProp: String?, subClassIntegerProp: Int?) {
        self.baseClassStringProp = baseClassStringProp
        self.baseClassIntegerProp = baseClassIntegerProp
        self.subClassStringProp = subClassStringProp
        self.subClassIntegerProp = subClassIntegerProp
    }


}

