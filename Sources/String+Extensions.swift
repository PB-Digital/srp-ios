//
//  String+Extensions.swift
//  srp-sample
//
//  Created by Karim Karimov on 26.05.24.
//

import Foundation

extension String {
    subscript(index: Int) -> Character {
        let requiredIndex = self.index(startIndex, offsetBy: index)
        return self[requiredIndex]
    }
    
    func removeLeadingZeroChars() -> String {
        guard self.count > 0 else {
            return self
        }
        
        var copy = self
        
        while copy[0] == "0" {
            copy.removeFirst()
        }
        return copy
    }
    
    func padZeroToEven() -> String {
        guard self.count % 2 == 1 else { return self }
        
        return "0\(self)"
    }
}
