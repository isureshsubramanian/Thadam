import Testing

@testable import ThadamNetKit

struct HostPeekTests {
    @Test func sniFromAClientHello() {
        #expect(sniHost(clientHello(sni: "API.Example.TEST")) == "api.example.test")
        #expect(peekHost(clientHello(sni: "api.example.test"))?.from == .sni)
    }

    @Test func truncatedClientHellosNeverCrash() {
        let full = clientHello(sni: "api.example.test")
        for length in 0..<full.count {
            #expect(sniHost(Array(full.prefix(length))) == nil, "length \(length)")
        }
    }

    @Test func sniThatIsNotAHostNameIsDropped() {
        #expect(sniHost(clientHello(sni: "bad host/path")) == nil)
        #expect(sniHost(clientHello(sni: String(repeating: "a", count: 64) + ".test")) == nil)
    }

    @Test func httpHostWithoutThePath() throws {
        let request = Array("GET /private/path?token=abc HTTP/1.1\r\nUser-Agent: x\r\nHost: Example.TEST:8080\r\n\r\n".utf8)
        let found = try #require(peekHost(request))
        #expect(found.host == "example.test")
        #expect(found.from == .http)
        #expect(!found.host.contains("private") && !found.host.contains("token"))
    }

    @Test func httpWithoutAUsableHost() {
        let cases = [
            "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n",
            "GET / HTTP/1.1\r\nAccept: */*\r\n\r\nHost: late.example.test\r\n",
            "GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n",
            "BREW / HTTP/1.1\r\nHost: pot.example.test\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: partial.example.te",
            "",
        ]
        for request in cases {
            #expect(peekHost(Array(request.utf8)) == nil, "\(request.debugDescription)")
        }
    }

    @Test func garbageAndOverLongInputNeverCrash() {
        var random = SeededBytes(state: 7)
        for length in [1, 5, 64, 517, 4096, 20_000] {
            _ = peekHost(random.bytes(length))
            _ = peekHost([0x16, 0x03, 0x01, 0xFF, 0xFF] + random.bytes(length))
        }
        let long = Array("GET / HTTP/1.1\r\n".utf8) + [UInt8](repeating: 0x61, count: 10_000)
        #expect(peekHost(long) == nil)
    }

    @Test func hostNamesFollowTheCollectorsRule() {
        #expect(normalizedHost("api.example.test") == "api.example.test")
        #expect(normalizedHost("_dmarc.Example.TEST.") == "_dmarc.example.test")
        #expect(normalizedHost("") == nil)
        #expect(normalizedHost(".") == nil)
        #expect(normalizedHost("a..test") == nil)
        #expect(normalizedHost("a b.test") == nil)
        #expect(normalizedHost(String(repeating: "a", count: 64) + ".test") == nil)
        let longest = Array(repeating: String(repeating: "a", count: 62), count: 4).joined(separator: ".") + ".a"
        #expect(longest.count == 253 && normalizedHost(longest) != nil)
        #expect(normalizedHost(longest + "a") == nil)
    }
}
