import Foundation
import Cryptor

/// Creates the salted verification key based on a user's username and
/// password. Only the salt and verification key need to be stored on the
/// server, there's no need to keep the plain-text password. 
///
/// Keep the verification key private, as it can be used to brute-force 
/// the password from.
///
/// - Parameters:
///   - username: user's username
///   - password: user's password
///   - salt: (optional) custom salt value; if providing a salt, make sure to
///       provide a good random salt of at least 16 bytes. Default is to
///       generate a salt of 16 bytes.
///   - group: `Group` parameters; default is 2048-bits group.
///   - algorithm: which `Digest.Algorithm` to use; default is SHA1.
/// - Returns: salt (s) and verification key (v)
public func createSaltedVerificationKey(
    clientType: ClientType,
    username: String,
    password: String,
    salt: Data? = nil,
    group: Group = .N2048,
    algorithm: Digest.Algorithm = .sha1)
    -> (salt: String, verificationKeyHex: String)
{
    let salt = salt ?? Data(try! Random.generate(byteCount: 16))
    let saltStr = salt.hexEncodedString()
    
    let x: BInt
    
    switch clientType {
    case .nimbus:
        x = calculate_x_nimbus(algorithm: algorithm, salt: salt, password: password)
    case .thinbus:
        x = calculate_x_thinbus(group: group, algorithm: algorithm, salt: saltStr, username: username, password: password)
    }
   
    return createSaltedVerificationKey(from: x, salt: saltStr, group: group)
}

/// Creates the salted verification key based on a precomputed SRP x value.
/// Only the salt and verification key need to be stored on the
/// server, there's no need to keep the plain-text password.
///
/// Keep the verification key private, as it can be used to brute-force
/// the password from.
///
/// - Parameters:
///   - x: precomputed SRP x
///   - salt: (optional) custom salt value; if providing a salt, make sure to
///       provide a good random salt of at least 16 bytes. Default is to
///       generate a salt of 16 bytes.
///   - group: `Group` parameters; default is 2048-bits group.
/// - Returns: salt (s) and verification key (v)
func createSaltedVerificationKey(
    from x: BInt,
    salt: String? = nil,
    group: Group = .N2048)
    -> (salt: String, verificationKeyHex: String)
{
    let saltStr = salt ?? Data(try! Random.generate(byteCount: 16)).hexEncodedString()
    
    let v = calculate_v(group: group, x: x)
    return (saltStr, v.asString(radix: 16))
}

func pad(_ data: Data, to size: Int) -> Data {
    precondition(size >= data.count, "Negative padding not possible")
    return Data(count: size - data.count) + data
}

//u = H(PAD(A) | PAD(B))
func calculate_u(group: Group, algorithm: Digest.Algorithm, A: Data, B: Data) -> BInt {
    let H = Digest.hasher(algorithm)
    let size = group.getNSize()
    return BInt(H(pad(A, to: size) + pad(B, to: size)).hexEncodedString(), radix: 16)!
}

//u = H(A | B)
func calculate_u_thinbus(group: Group, algorithm: Digest.Algorithm, A: String, B: String) -> BInt {
    let H = Digest.hasher(algorithm)
    let Adata = A.data(using: .utf8)!
    let Bdata = B.data(using: .utf8)!
    
    return BInt(H(Adata + Bdata).hexEncodedString(), radix: 16)!
}

//M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)
func calculate_M(group: Group, algorithm: Digest.Algorithm, username: String, salt: Data, A: Data, B: Data, K: Data) -> Data {
    let H = Digest.hasher(algorithm)
    let HN_xor_Hg = (H(Bignum.init(hex: group.N.asString(radix: 16)).data) ^ H(Bignum.init(hex: group.g.asString(radix: 16)).data))!
    let HI = H(username.data(using: .utf8)!)
    return H(HN_xor_Hg + HI + salt + A + B + K)
}

//M1 = H(A | B | S)
func calculate_M_nimbus(group: Group, algorithm: Digest.Algorithm, A: Data, B: Data, S: Data) -> Data {
    let H = Digest.hasher(algorithm)
    return H(A + B + S)
}

//M1 = H(A | B | S)
func calculate_M_thinbus(group: Group, algorithm: Digest.Algorithm, A: String, B: String, S: String) -> String {
    let Abytes = A.bytes
    let Bbytes = B.bytes
    let Sbytes = S.bytes

    let digest = Digest(using: algorithm)
    _ = digest.update(byteArray: Abytes)
    _ = digest.update(byteArray: Bbytes)
    _ = digest.update(byteArray: Sbytes)
    let finalDigest = digest.final()
    let result = Data(finalDigest)

    let evidence = Bignum(data: result)
    let evidendeHex = evidence.hex

    return evidendeHex
//    let H = Digest.hasher(algorithm)
//    return H((A + B + S).data)
}

//HAMK = H(A | M | K)
func calculate_HAMK(algorithm: Digest.Algorithm, A: Data, M: Data, K: Data) -> Data {
    let H = Digest.hasher(algorithm)
    return H(A + M + K)
}

//k = H(N | PAD(g))
func calculate_k(group: Group, algorithm: Digest.Algorithm) -> BInt {
    let H = Digest.hasher(algorithm)
    let size = group.getNSize()
    return BInt(H(Bignum.init(hex: group.N.asString(radix: 16)).data +
                    pad(Bignum.init(hex: group.g.asString(radix: 16)).data, to: size)).hexEncodedString(), radix: 16)!
}

//x = H(s | H(I | ":" | P))
func calculate_x_thinbus(group: Group, algorithm: Digest.Algorithm, salt: String, username: String, password: String) -> BInt {
    let H = Digest.hasher(algorithm)
    
    let hash1 = H("\(username):\(password)".data(using: .utf8)!)
    
    var hash1S = hash1.hexEncodedString()
    
    while hash1S.first == "0" {
        hash1S.remove(at: hash1S.startIndex)
    }
        
    let hash = H("\(salt)\(hash1S)".uppercased().data(using: .utf8)!)
    
    var hashS = hash.hexEncodedString()
    
    while hashS.first == "0" {
        hashS.remove(at: hashS.startIndex)
    }
        
    return BIntMath.mod_exp(BInt(hashS, radix: 16)!, BInt(1), group.N)
}

//x = H(s | H(P))
func calculate_x_nimbus(algorithm: Digest.Algorithm, salt: Data, password: String) -> BInt {
    let H = Digest.hasher(algorithm)
    return BInt(H(salt + H(password.data(using: .utf8)!)).hexEncodedString(), radix: 16)!
}

// v = g^x % N
func calculate_v(group: Group, x: BInt) -> BInt {
    return BIntMath.mod_exp(group.g, x, group.N)
}
