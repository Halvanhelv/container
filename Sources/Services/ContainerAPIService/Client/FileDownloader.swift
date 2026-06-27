//===----------------------------------------------------------------------===//
// Copyright © 2026 Apple Inc. and the container project authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//===----------------------------------------------------------------------===//

import AsyncHTTPClient
import ContainerizationError
import ContainerizationExtras
import CryptoKit
import Foundation
import TerminalProgress

public struct FileDownloader {
    /// Downloads `url` to `destination`.
    ///
    /// - Parameter expectedSHA256: When provided, the downloaded file is hashed and
    ///   compared against this digest. On mismatch the partial file is removed and the
    ///   call throws, so a tampered or corrupted download is never left on disk. The
    ///   value is matched case-insensitively and may carry an optional `sha256:` prefix.
    public static func downloadFile(
        url: URL,
        to destination: URL,
        expectedSHA256: String? = nil,
        progressUpdate: ProgressUpdateHandler? = nil
    ) async throws {
        let request = try HTTPClient.Request(url: url)

        let delegate = try FileDownloadDelegate(
            path: destination.path(),
            reportHead: {
                let expectedSizeString = $0.headers["Content-Length"].first ?? ""
                if let expectedSize = Int64(expectedSizeString) {
                    if let progressUpdate {
                        Task {
                            await progressUpdate([
                                .addTotalSize(expectedSize)
                            ])
                        }
                    }
                }
            },
            reportProgress: {
                let receivedBytes = Int64($0.receivedBytes)
                if let progressUpdate {
                    Task {
                        await progressUpdate([
                            .setSize(receivedBytes)
                        ])
                    }
                }
            })

        let client = FileDownloader.createClient(url: url)
        do {
            _ = try await client.execute(request: request, delegate: delegate).get()
        } catch {
            try? await client.shutdown()
            throw error
        }
        try await client.shutdown()

        if let expectedSHA256 {
            do {
                try verifySHA256(file: destination, expected: expectedSHA256)
            } catch {
                // A file that fails integrity verification must not be left on disk
                // where a later step could pick it up as if it were trusted.
                try? FileManager.default.removeItem(at: destination)
                throw error
            }
        }
    }

    /// Verifies that the SHA-256 digest of `file` matches `expected`.
    ///
    /// `expected` is compared case-insensitively and may include an optional `sha256:`
    /// algorithm prefix. Throws when the file cannot be read or the digest differs.
    public static func verifySHA256(file: URL, expected: String) throws {
        let normalizedExpected = Self.normalizeDigest(expected)
        let actual = try Self.computeSHA256(file: file)
        guard actual == normalizedExpected else {
            throw ContainerizationError(
                .invalidState,
                message: "integrity check failed for \(file.path): expected sha256 \(normalizedExpected), got \(actual)"
            )
        }
    }

    /// Lowercases the digest and strips an optional `sha256:` algorithm prefix for comparison.
    private static func normalizeDigest(_ digest: String) -> String {
        // Lowercase before stripping so a mixed- or upper-case prefix (e.g. `SHA256:`) is
        // also removed, matching the case-insensitive contract.
        let lowered = digest.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return lowered.hasPrefix("sha256:") ? String(lowered.dropFirst("sha256:".count)) : lowered
    }

    /// Streams `file` through a SHA-256 hasher and returns the lowercase hex digest.
    private static func computeSHA256(file: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }

        var hasher = SHA256()
        let chunkSize = 1 << 20  // 1 MiB; bounded memory for large kernel archives
        while case let chunk = handle.readData(ofLength: chunkSize), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func createClient(url: URL) -> HTTPClient {
        var httpConfiguration = HTTPClient.Configuration()
        // for large file downloads we keep a generous connect timeout, and
        // no read timeout since download durations can vary
        httpConfiguration.timeout = HTTPClient.Configuration.Timeout(
            connect: .seconds(30),
            read: .none
        )
        if let host = url.host {
            let proxyURL = ProxyUtils.proxyFromEnvironment(scheme: url.scheme, host: host)
            if let proxyURL, let proxyHost = proxyURL.host {
                httpConfiguration.proxy = HTTPClient.Configuration.Proxy.server(host: proxyHost, port: proxyURL.port ?? 8080)
            }
        }

        return HTTPClient(eventLoopGroupProvider: .singleton, configuration: httpConfiguration)
    }
}
