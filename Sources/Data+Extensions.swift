import Foundation

func ^ (lhs: Data, rhs: Data) -> Data? {
    guard lhs.count == rhs.count else { return nil }
    var result = Data(count: lhs.count)
    for index in lhs.indices {
        result[index] = lhs[index] ^ rhs[index]
    }
    return result
}

// Removed in Xcode 8 beta 3
func + (lhs: Data, rhs: Data) -> Data {
    var result = lhs
    result.append(rhs)
    return result
}

extension DataProtocol {
    public func hexEncodedString(uppercase: Bool = false) -> String {
        return self.map {
            if $0 < 16 {
                return "0" + String($0, radix: 16, uppercase: uppercase)
            } else {
                return String($0, radix: 16, uppercase: uppercase)
            }
        }.joined()
    }
}

extension StringProtocol {
    public var hexData: Data { .init(hex) }
    private var hex: UnfoldSequence<UInt8, Index> {
        sequence(state: startIndex) { startIndex in
            guard startIndex < self.endIndex else { return nil }
            let endIndex = self.index(startIndex, offsetBy: 2, limitedBy: self.endIndex) ?? self.endIndex
            defer { startIndex = endIndex }
            return UInt8(self[startIndex..<endIndex], radix: 16)
        }
    }
}

extension Data {
    public var bytes: [UInt8] {
        return [UInt8](self)
    }
    
    func normalize() -> Data {
        var byteArr = self.bytes
        
        while true, !byteArr.isEmpty {
            if byteArr.first == 0 {
                byteArr.remove(at: 0)
            } else {
                break
            }
        }
        
        return Data(byteArr)
    }
}
