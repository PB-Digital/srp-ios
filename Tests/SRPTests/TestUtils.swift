import Cryptor
import Foundation
import SRP

enum DataDecodingError: Error {
    case oddStringLength(Int)
}

extension Data {
    init(hex: String) throws {
        if hex.utf8.count % 2 == 1 {
            throw DataDecodingError.oddStringLength(hex.utf8.count)
        }
        let bytes = stride(from: 0, to: hex.utf8.count, by: 2)
            .map { hex.utf8.index(hex.utf8.startIndex, offsetBy: $0) }
            .map { hex.utf8[$0...hex.utf8.index(after: $0)] }
            .map { UInt8(String($0)!, radix: 16)! }
        self.init(bytes: bytes)
    }
    var hex: String {
        return map { String(format: "%02hhx", $0) }.joined()
    }
}

let remotepy = URL(fileURLWithPath: #file)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("remote.py")

enum RemoteError: Error {
    case noPython
    case unexpectedPrompt(String)
    case commandFailure
    case commandFailureWithMessage(String)
    case valueExpected
    case unexpectedValueLabel(String)
    case decodingError
    case unexpectedExit
}

class Remote {
    private let process: Process

    fileprivate let input = Pipe()
    fileprivate let output = BufferedPipe()
    fileprivate let error = BufferedPipe()

    class BufferedPipe {
        let pipe = Pipe()
        var buffer = Data()

        var fileHandleForReading: FileHandle {
            return pipe.fileHandleForReading
        }

        var fileHandleForWriting: FileHandle {
            return pipe.fileHandleForWriting
        }
    }

    fileprivate init(process: Process) {
        self.process = process

        process.standardInput = input
        process.standardOutput = output.pipe
        process.standardError = error.pipe

        process.launch()
    }


    fileprivate func write(prompt expectedPrompt: String, line: String) throws {
        #if DEBUG
            print("DEBUG: Expecting prompt '\(expectedPrompt)'")
        #endif
        let prompt = try readprompt(from: output)
        guard prompt == "\(expectedPrompt): " else {
            throw RemoteError.unexpectedPrompt(prompt)
        }
        writeline(line)
    }

    private func writeline(_ line: String) {
        input.fileHandleForWriting.write("\(line)\n".data(using: .ascii)!)

        #if DEBUG
            print("DEBUG: > \(line)")
        #endif
    }

    private func readprompt(from pipe: BufferedPipe) throws -> String {
        if !process.isRunning {
            throw RemoteError.unexpectedExit
        }
        if pipe.buffer.count > 0 {
            defer { pipe.buffer = Data() }
            return String(data: pipe.buffer, encoding: .ascii)!
        } else {
            let availableData = pipe.fileHandleForReading.availableData
            guard let prompt = String(data: availableData, encoding: .ascii) else {
                throw RemoteError.decodingError
            }
            #if DEBUG
                print("DEBUG: < \(prompt)")
            #endif
            return prompt
        }
    }

    fileprivate func read(label: String, from pipe: BufferedPipe) throws -> (String) {
        #if DEBUG
            print("DEBUG: Expecting label '\(label)'")
        #endif
        let splitted = try readline(from: pipe).components(separatedBy: ": ")
        guard splitted.count == 2 else {
            #if DEBUG
                print("ERROR: \(readError())")
            #endif
            throw RemoteError.valueExpected
        }
        guard label == splitted[0] else {
            #if DEBUG
                print("ERROR: \(readError())")
            #endif
            throw RemoteError.unexpectedValueLabel(splitted[0])
        }
        return splitted[1]
    }

    fileprivate func readline(from pipe: BufferedPipe) throws -> String {
        while true {
            if let eol = pipe.buffer.index(of: 10) {
                defer {
                    // Slicing of Data is broken on Linux... workaround by creating new Data.
                    pipe.buffer = Data(pipe.buffer.dropFirst(eol - pipe.buffer.startIndex + 1))
                }
                guard let line = String(data: Data(pipe.buffer[pipe.buffer.startIndex..<eol]), encoding: .utf8) else {
                    throw RemoteError.decodingError
                }
                return line
            } else if pipe.buffer.count > 0 {
                #if DEBUG
                    print("DEBUG: Available buffer, but without a newline")
                #endif
            }

            let availableData = pipe.fileHandleForReading.availableData
            pipe.buffer.append(availableData)

            #if DEBUG
                if let availableOutput = String(data: availableData, encoding: .utf8) {
                    for line in availableOutput.characters.split(separator: "\n") {
                        print("DEBUG: < \(String(line))")
                    }
                } else {
                    print("DEBUG: Could not decode output")
                }
            #endif

            if availableData.count == 0 && !process.isRunning {
                // No more data coming and buffer doesn't contain a newline
                throw RemoteError.unexpectedExit
            }
        }
    }

    fileprivate func readError() -> RemoteError {
        let errorData = error.fileHandleForReading.readDataToEndOfFile()
        guard let message = String(data: errorData, encoding: .utf8) else {
            return RemoteError.commandFailure
        }
        return RemoteError.commandFailureWithMessage(message)
    }
}

class RemoteServer: Remote {
    var verificationKey: Data? = nil
    var privateKey: Data? = nil
    var salt: Data? = nil
    var publicKey: Data? = nil
    var expectedM: Data? = nil

    /// Start remote.py in server-mode. The saltedVerificationKey is
    /// generated by the Python script.
    ///
    /// - Parameters:
    ///   - username:
    ///   - password:
    ///   - group:
    ///   - algorithm:
    ///   - privateKey:
    ///   - salt:
    /// - Throws: on I/O Error
    init(
        username: String,
        password: String,
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        privateKey: Data? = nil,
        salt: Data? = nil)
        throws
    {
        guard let python = ProcessInfo.processInfo.environment["PYTHON"] else {
            throw RemoteError.noPython
        }

        let remotepy = URL(fileURLWithPath: #file)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("remote.py")

        let process = Process()
        process.launchPath = python
        process.arguments = [remotepy.path,
                             "server",
                             username.data(using: .utf8)!.hex,
                             password.data(using: .utf8)!.hex,
                             "--group", "\(group)",
                             "--algorithm", "\(algorithm)"]
        if let privateKey = privateKey {
            process.arguments!.append(contentsOf: ["--private", privateKey.hex])
        }
        if let salt = salt {
            process.arguments!.append(contentsOf: ["--salt", salt.hex])
        }
        super.init(process: process)

        verificationKey = try Data(hex: read(label: "v", from: error))
    }

    /// Get server's challenge
    ///
    /// - Parameter publicKey: client's public key
    /// - Returns: (salt, publicKey)
    /// - Throws: on I/O Error
    func getChallenge(publicKey A: Data) throws -> (salt: Data, publicKey: Data) {
        do {
            try write(prompt: "A", line: A.hex)
            privateKey = try Data(hex: try read(label: "b", from: error))
            salt = try Data(hex: try read(label: "s", from: output))
            publicKey = try Data(hex: try read(label: "B", from: output))
            return (salt!, publicKey!)
        } catch RemoteError.unexpectedExit {
            throw readError()
        }
    }

    /// Verify the client's response
    ///
    /// - Parameter keyProof: client's key proof (M)
    /// - Returns: server's key proof (H(A|M|K))
    /// - Throws: on I/O Error
    func verifySession(keyProof M: Data) throws -> Data {
        do {
            try write(prompt: "M", line: M.hex)
            expectedM = try Data(hex: try read(label: "expected M", from: error))
            return try Data(hex: try read(label: "HAMK", from: output))
        } catch RemoteError.unexpectedExit {
            throw readError()
        }
    }

    /// Returns the server's session key
    ///
    /// - Returns: session key
    /// - Throws: on I/O Error
    func getSessionKey() throws -> Data {
        return try Data(hex: try read(label: "K", from: error))
    }
}

class RemoteClient: Remote {
    let username: String
    var privateKey: Data? = nil
    var publicKey: Data? = nil

    /// Start remote.py in client-mode.
    ///
    /// - Parameters:
    ///   - username:
    ///   - password:
    ///   - group:
    ///   - algorithm:
    ///   - privateKey:
    /// - Throws: on I/O Error
    init(
        username: String,
        password: String,
        group: Group = .N2048,
        algorithm: Digest.Algorithm = .sha1,
        privateKey: Data? = nil)
        throws
    {
        self.username = username

        guard let python = ProcessInfo.processInfo.environment["PYTHON"] else {
            throw RemoteError.noPython
        }

        let process = Process()
        process.launchPath = python
        process.arguments = [remotepy.path,
                             "client",
                             username.data(using: .utf8)!.hex,
                             password.data(using: .utf8)!.hex,
                             "--group", "\(group)",
                             "--algorithm", "\(algorithm)"]
        if let privateKey = privateKey {
            process.arguments!.append(contentsOf: ["--private", privateKey.hex])
        }
        super.init(process: process)

        self.privateKey = try Data(hex: try read(label: "a", from: error))
    }

    /// Read public key from stdout.
    ///
    /// - Returns: `username` (I) and `publicKey` (A)
    /// - Throws: on I/O Error
    func startAuthentication() throws -> (username: String, publicKey: Data) {
        publicKey = try Data(hex: try read(label: "A", from: output))
        return (username, publicKey!)
    }

    /// Process challenge, get client's response
    ///
    /// - Parameters:
    ///   - salt:
    ///   - publicKey:
    /// - Returns: key proof (M)
    /// - Throws: on I/O Error
    func processChallenge(salt s: Data, publicKey B: Data) throws -> Data {
        try write(prompt: "s", line: s.hex)
        try write(prompt: "B", line: B.hex)
        return try Data(hex: try read(label: "M", from: output))
    }

    /// Verify the server's response.
    ///
    /// - Parameter keyProof: (M)
    /// - Throws: on I/O Error
    func verifySession(keyProof: Data) throws {
        try write(prompt: "HAMK", line: keyProof.hex)
        guard try readline(from: output) == "OK" else {
            throw readError()
        }
    }

    /// Returns the client's session key
    ///
    /// - Returns: session key (K)
    /// - Throws: on I/O Error
    func getSessionKey() throws -> Data {
        return try Data(hex: try read(label: "K", from: error))
    }
}
