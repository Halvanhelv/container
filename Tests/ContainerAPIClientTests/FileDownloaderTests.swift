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

import ContainerizationError
import Foundation
import Testing

@testable import ContainerAPIClient

struct FileDownloaderTests {

    /// Writes `contents` to a unique temporary file and returns its URL.
    private func makeTempFile(contents: Data) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).bin")
        try contents.write(to: url)
        return url
    }

    // MARK: - verifySHA256

    @Test
    func testVerifySucceedsWhenDigestMatches() throws {
        // SHA-256 of "abc"
        let file = try makeTempFile(contents: Data("abc".utf8))
        defer { try? FileManager.default.removeItem(at: file) }

        try FileDownloader.verifySHA256(
            file: file,
            expected: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    @Test
    func testVerifyAcceptsUppercaseAndAlgorithmPrefix() throws {
        let file = try makeTempFile(contents: Data("abc".utf8))
        defer { try? FileManager.default.removeItem(at: file) }

        try FileDownloader.verifySHA256(
            file: file,
            expected: "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
        )
    }

    @Test
    func testVerifyAcceptsUppercaseAlgorithmPrefix() throws {
        let file = try makeTempFile(contents: Data("abc".utf8))
        defer { try? FileManager.default.removeItem(at: file) }

        try FileDownloader.verifySHA256(
            file: file,
            expected: "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
    }

    @Test
    func testVerifySucceedsForEmptyFile() throws {
        let file = try makeTempFile(contents: Data())
        defer { try? FileManager.default.removeItem(at: file) }

        // SHA-256 of the empty input
        try FileDownloader.verifySHA256(
            file: file,
            expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
    }

    @Test
    func testVerifyThrowsWhenDigestMismatches() throws {
        let file = try makeTempFile(contents: Data("abc".utf8))
        defer { try? FileManager.default.removeItem(at: file) }

        #expect(throws: ContainerizationError.self) {
            try FileDownloader.verifySHA256(
                file: file,
                expected: "0000000000000000000000000000000000000000000000000000000000000000"
            )
        }
    }

    @Test
    func testVerifyThrowsForMissingFile() throws {
        let missing = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(UUID().uuidString).bin")

        #expect(throws: (any Error).self) {
            try FileDownloader.verifySHA256(
                file: missing,
                expected: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
        }
    }
}
