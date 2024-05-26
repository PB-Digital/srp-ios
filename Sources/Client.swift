import Foundation
import Cryptor
import BigInt

// SRP client side impl for Thinbus routines
// https://github.com/simbo1905/thinbus-srp-npm
public class Client {
    // private key
    let a: BigUInt
    // public key
    let A: BigUInt

    let group: Group
    let algorithm: Digest.Algorithm

    let username: String
    var password: String

    public private(set) var isAuthenticated = false

    init(
        username: String,
        password: String,
        group: Group = .N256,
        algorithm: Digest.Algorithm = .sha256
    ) {
        self.username = username
        self.password = password
        
        self.group = group
        self.algorithm = algorithm
        
        var tempa: BigUInt
        var tempA: BigUInt
        
        repeat {
            let randomBytes = Data(try! Random.generate(byteCount: 32)).hexEncodedString()
            
            tempa = BigUInt(randomBytes.hexaData)
            
            // A = g^a % N
            tempA = group.g.power(tempa, modulus: group.N)
        } while tempA.serialize().hexEncodedString().count % 2 == 1
        
        a = tempa
        A = tempA
    }

    public func startAuthentication() -> (username: String, publicKey: Data) {
        return (username, publicKey)
    }

    public func processChallenge(
        salt: String,
        publicKey serverPublicKey: String) throws -> String {
        
        let N = group.N
        
        let strB: String = serverPublicKey.padZeroToEven()

        let B = BigUInt(strB.hexaData)

        guard B % N != 0 else {
            throw AuthenticationFailure.invalidPublicKey
        }
       
        let k = calculate_k()

        let u: BigUInt = calculate_u(
            A: publicKey.hexEncodedString().data,
            B: strB.removeLeadingZeroChars().data)
        
        let x: BigUInt = calculate_x(
            salt: salt,
            username: username,
            password: password)
        
        let v = calculate_v(group: group, x: x)
            
        // shared secret
        let S = (B + N - k * v % N).power(a + u * x, modulus: N)

        let Shex = S.serialize().hexEncodedString()

        // client verification
        let M = calculate_M(
            A: publicKey.hexEncodedString(),
            B: strB.removeLeadingZeroChars(),
            S: Shex)
            
        let MHex = M.serialize().hexEncodedString()
            
        return MHex
    }
    
    public var publicKey: Data {
        return A.serialize()
    }
    
    public var privateKey: Data {
        return a.serialize()
    }
    
    // MARK: - SRP methods

    //u = H(A | B)
    private func calculate_u(A: Data, B: Data) -> BigUInt {
        let H = Digest.hasher(self.algorithm)
        return BigUInt(H(A + B))
    }

    //M1 = H(A | B | S)
    private func calculate_M(A: String, B: String, S: String) -> BigUInt {
        let Abytes = A.bytes
        let Bbytes = B.bytes
        let Sbytes = S.bytes

        let digest = Digest(using: self.algorithm)
        _ = digest.update(byteArray: Abytes)
        _ = digest.update(byteArray: Bbytes)
        _ = digest.update(byteArray: Sbytes)
        let finalDigest = digest.final()
        let result = Data(finalDigest)

        return BigUInt(result)
    }

    //k = H(N | PAD(g))
    private func calculate_k() -> BigUInt {
        let H = Digest.hasher(self.algorithm)
        let size = self.group.getNSize()
        let N = BigUInt(self.group.N.serialize()).serialize()
        let g = BigUInt(self.group.g.serialize()).serialize()
        let padg = self.pad(g, to: size)
        
        return BigUInt(H(N + padg))
    }

    //x = H(s | H(I | ":" | P))
    private func calculate_x(
        salt: String,
        username: String,
        password: String
    ) -> BigUInt {
        let H = Digest.hasher(algorithm)
        
        let credentialsHash = H("\(username):\(password)".data)
                .hexEncodedString()
                .removeLeadingZeroChars()
        
        let hash = H("\(salt)\(credentialsHash)".uppercased().data)
                .hexEncodedString()
                .removeLeadingZeroChars()
        
        return BigUInt(hash.hexaData) % group.N
    }

    // v = g^x % N
    func calculate_v(group: Group, x: BigUInt) -> BigUInt {
        return group.g.power(x, modulus: group.N)
    }

    public func createSaltedVerificationKey(
        username: String,
        password: String,
        salt: Data
    ) -> (salt: String, verificationKeyHex: String) {
        let saltStr = salt.hexEncodedString()
        
        let x: BigUInt = self.calculate_x(
            salt: saltStr,
            username: username,
            password: password
        )
        
        let v = calculate_v(group: group, x: x)
        let vHex = v.serialize().hexEncodedString()
        
        return (saltStr, vHex)
    }
    
    private func pad(_ data: Data, to size: Int) -> Data {
        precondition(size >= data.count, "Negative padding not possible")
        return Data(count: size - data.count) + data
    }
}
