import Foundation
import Cryptor
import BigInt
import Sodium

/// SRP Client; the party that initializes the authentication and
/// must proof possession of the correct password.
public class Client {
    let a: BigUInt
    let A: BigUInt
    
    let group: Group
    let algorithm: Digest.Algorithm
    
    let username: String
    var password: String
    var precomputedX: BigUInt? = nil
    
    var HAMK: Data?
    var K: Data?
    
    /// Whether the session is authenticated, i.e. the password
    /// was verified by the server and proof of a valid session
    /// key was provided by the server. If `true`, `sessionKey`
    /// is also available.
    public private(set) var isAuthenticated = false
    
    /// Initialize the Client SRP party with a password.
    ///
    /// - Parameters:
    ///   - username: user's username.
    ///   - password: user's password.
    ///   - group: which `Group` to use, must be the same for the
    ///       server as well as the pre-stored verificationKey.
    ///   - algorithm: which `Digest.Algorithm` to use, again this
    ///       must be the same for the server as well as the pre-stored
    ///       verificationKey.
    ///   - privateKey: (optional) custom private key (a); if providing
    ///       the private key of the `Client`, make sure to provide a
    ///       good random key of at least 32 bytes. Default is to
    ///       generate a private key of 128 bytes. You MUST not re-use
    ///       the private key between sessions.
    public init(
        username: String,
        password: String,
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        privateKey: Data? = nil,
        precomputedX: Data? = nil)
    {
        self.username = username
        self.password = password
        self.group = group
        self.algorithm = algorithm
        
        if let privateKey = privateKey {
            a = BigUInt(privateKey.hexEncodedString(), radix: 16)!
        } else {
            
            let sodium = Sodium()
            let curve25519KeyPair = sodium.box.keyPair()
            let privateKey = curve25519KeyPair!.secretKey
            
            a = BigUInt(privateKey.hexEncodedString(), radix: 16)!
        }
        
        // A = g^a % N
        A = group.g.power(a, modulus: group.N)
        
        if let preX = precomputedX {
            self.precomputedX = BigUInt(preX)
        }
    }
    
    /// Starts authentication. This method is a no-op.
    ///
    /// - Returns: `username` (I) and `publicKey` (A)
    public func startAuthentication() -> (username: String, publicKey: Data) {
        return (username, publicKey)
    }
    
    /// Process the challenge provided by the server. This sets the `sessionKey`
    /// and generates proof that it generated the correct key from the password
    /// and the challenge. After the server has also proven the validity of their
    /// key, the `sessionKey` can be used.
    ///
    /// - Parameters:
    ///   - salt: user-specific salt (s)
    ///   - publicKey: server's public key (B)
    /// - Returns: key proof (M)
    /// - Throws: `AuthenticationFailure.invalidPublicKey` if the server's
    ///     public key is invalid (i.e. B % N is zero).
    public func processChallenge(
        clientType: ClientType,
        salt: Data,
        publicKey serverPublicKey: Data) throws -> Data
    {
        
        let H = Digest.hasher(algorithm)
        let N = group.N
        
        let B = BigUInt(serverPublicKey)
        
        guard B % N != 0 else {
            throw AuthenticationFailure.invalidPublicKey
        }
        
        let k = calculate_k(group: group, algorithm: algorithm)
        
        let u: BigUInt
        let x: BigUInt
        
        switch clientType {
        case .nimbus:
            u = calculate_u(group: group, algorithm: algorithm, A: publicKey, B: serverPublicKey)
            x = self.precomputedX ?? calculate_x_nimbus(algorithm: algorithm, salt: salt, password: password)
        case .thinbus:
            u = calculate_u_thinbus(group: group,
                                    algorithm: algorithm,
                                    A: publicKey,
                                    B: serverPublicKey)
            
            x = self.precomputedX ?? calculate_x_thinbus(group: group,
                                                         algorithm: algorithm,
                                                         salt: salt,
                                                         username: username,
                                                         password: password)
        }
        
        let v = calculate_v(group: group, x: x)
        
        // shared secret
        // S = (B - kg^x) ^ (a + ux)
        // Note that v = g^x, and that B - kg^x might become negative, which
        // cannot be stored in BigUInt. So we'll add N to B_ and make sure kv
        // isn't greater than N.
        let S = (B + N - k * v % N).power(a + u * x, modulus: N)
        
        // session key
        K = H(S.serialize())
        
        // client verification
        let M: Data
        
        switch clientType {
        case .nimbus:
            M = calculate_M_nimbus(group: group,
                                   algorithm: algorithm,
                                   A: publicKey,
                                   B: B.serialize(),
                                   S: S.serialize())
        case .thinbus:
            M = calculate_M_thinbus(group: group,
                                    algorithm: algorithm,
                                    A: publicKey,
                                    B: B.serialize(),
                                    S: S.serialize())
        }
        
        // server verification
        HAMK = calculate_HAMK(algorithm: algorithm, A: publicKey, M: M, K: K!)
        
        return M
    }
    
    /// After the server has verified that the password is correct,
    /// it will send proof of the derived session key. This is verified
    /// on our end and finalizes the authentication session. After this
    /// step, the `sessionKey` is available.
    ///
    /// - Parameter HAMK: proof of the server that it derived the same
    ///     session key.
    /// - Throws:
    ///    - `AuthenticationFailure.missingChallenge` if this method
    ///      is called before calling `processChallenge`.
    ///    - `AuthenticationFailure.keyProofMismatch` if the proof
    ///      doesn't match our own.
    public func verifySession(keyProof serverKeyProof: Data) throws {
        guard let HAMK = HAMK else {
            throw AuthenticationFailure.missingChallenge
        }
        guard HAMK == serverKeyProof else {
            throw AuthenticationFailure.keyProofMismatch
        }
        isAuthenticated = true
    }
    
    /// The client's public key (A). For every authentication
    /// session a new public key is generated.
    public var publicKey: Data {
        return A.serialize()
    }
    
    /// The client's private key (a). For every authentication
    /// session a new random private key is generated.
    public var privateKey: Data {
        return a.serialize()
    }
    
    /// The session key (K) that is exchanged during authentication.
    /// This key can be used to encrypt further communication
    /// between client and server.
    public var sessionKey: Data? {
        guard isAuthenticated else {
            return nil
        }
        return K
    }
}
