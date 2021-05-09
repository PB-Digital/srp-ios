import Foundation
import Cryptor

/// SRP Client; the party that initializes the authentication and
/// must proof possession of the correct password.
public class Client {
    let a: BInt
    let A: BInt

    let group: Group
    let algorithm: Digest.Algorithm

    let username: String
    var password: String?
    var precomputedX: BInt?

    var HAMK: Data?
    var K: Data?

    /// Whether the session is authenticated, i.e. the password
    /// was verified by the server and proof of a valid session
    /// key was provided by the server. If `true`, `sessionKey`
    /// is also available.
    public private(set) var isAuthenticated = false

    private init(
        username: String,
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        privateKey: Data? = nil)
    {
        self.username = username
        self.group = group
        self.algorithm = algorithm
        
        if let privateKey = privateKey {
            a = BInt(privateKey.hexEncodedString(), radix: 16)!
            
            // A = g^a % N
            A = BIntMath.mod_exp(group.g, a, group.N)
        } else {
            
            var tempa = BInt.init(randomByteCount: 32)
            
            // A = g^a % N
            var tempA = BIntMath.mod_exp(group.g, tempa, group.N)
            
            while tempA.asString(radix: 16).count % 2 == 1 {
                tempa = BInt.init(randomByteCount: 32)
                tempA = BIntMath.mod_exp(group.g, tempa, group.N)
            }
            
            a = tempa
            A = tempA
        }
    }

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
    public convenience init(
        username: String,
        password: String,
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        privateKey: Data? = nil)
    {
        self.init(username: username, group: group, algorithm: algorithm, privateKey: privateKey)
        self.password = password
    }

    /// Initialize the Client SRP party with a precomputed x.
    ///
    /// - Parameters:
    ///   - username: user's username.
    ///   - precomputedX: precomputed SRP x.
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
    public convenience init(
        username: String,
        precomputedX: Data,
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        privateKey: Data? = nil)
    {
        self.init(username: username, group: group, algorithm: algorithm, privateKey: privateKey)
        self.precomputedX = BInt(precomputedX.hexEncodedString(), radix: 16)!
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
        salt: String,
        publicKey serverPublicKey: String) throws -> String {
        
        let H = Digest.hasher(algorithm)
        let N = group.N
        
        var strB = serverPublicKey
        
        if clientType == .nimbus,
           strB.count != 64,
           strB.count % 2 == 1 {
            strB = "0\(strB)"
        }

        let B = BInt(strB, radix: 16)!
    
        guard BIntMath.mod_exp(B, BInt(1), N) != BInt(0) else {
            throw AuthenticationFailure.invalidPublicKey
        }
        
        let k = calculate_k(group: group, algorithm: algorithm)

        let u: BInt
        let x: BInt
        
        switch clientType {
        case .nimbus:
            u = calculate_u(group: group, algorithm: algorithm, A: publicKey, B: strB.hexaData)
            x = self.precomputedX ?? calculate_x_nimbus(algorithm: algorithm, salt: salt.hexaData, password: password!)
        case .thinbus:
            u = calculate_u_thinbus(group: group,
                                    algorithm: algorithm,
                                    A: publicKeyStr,
                                    B: strB)
            
            x = self.precomputedX ?? calculate_x_thinbus(group: group,
                                                         algorithm: algorithm,
                                                         salt: salt,
                                                         username: username,
                                                         password: password!)
        }
        
        let v = calculate_v(group: group, x: x)
        
        // shared secret
        // S = (B - kg^x) ^ (a + ux)
        // Note that v = g^x, and that B - kg^x might become negative, which
        // cannot be stored in BigUInt. So we'll add N to B_ and make sure kv
        // isn't greater than N.
        let diff = BIntMath.nnmod(k * v, N)
        let S = BIntMath.mod_exp(B + N - diff, a + (u * x), N)

        let Shex = S.asString(radix: 16)

        let Sdata = Bignum.init(hex: Shex).data

        // session key
        K = H(Sdata)

        // client verification
        let M: String
        
        switch clientType {
        case .nimbus:
            M = calculate_M_nimbus(group: group,
                                   algorithm: algorithm,
                                   A: publicKey,
                                   B: strB.hexaData,
                                   S: Sdata).hexEncodedString()
        case .thinbus:
            M = calculate_M_thinbus(group: group,
                                    algorithm: algorithm,
                                    A: publicKeyStr,
                                    B: strB,
                                    S: Shex)
        }
        
        // server verification
        HAMK = calculate_HAMK(algorithm: algorithm, A: publicKey, M: M.data, K: K!)
        
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
        return Bignum.init(hex: A.asString(radix: 16)).data
    }
    
    /// The client's public key (A). For every authentication
    /// session a new public key is generated.
    public var publicKeyStr: String {
        return A.asString(radix: 16)
    }

    /// The client's private key (a). For every authentication
    /// session a new random private key is generated.
    public var privateKey: Data {
        return Bignum.init(hex: a.asString(radix: 16)).data
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
