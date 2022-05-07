import Cryptor
import Foundation

extension Digest {
    static public func hasher(_ algorithm: Algorithm) -> (Data) -> Data {
        return { data in
            let result = Digest(using: algorithm)
                .update(data: data)!
                .final()
            return Data(bytes: result)
        }
    }
}
