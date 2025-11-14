#include <cstddef>
#include <cstdint>
#include <vector>
#include "../ipfixprobe/src/plugins/process/common/tlsParser/tlsParser.hpp"

using namespace ipxp::process;

bool parseClientHelloExtensions(TLSParser &parser) noexcept
{
    return parser.parseExtensions([&](const TLSExtension &extension)
                                  {
		switch (extension.type) {
		case TLSExtensionType::SERVER_NAME: {
			auto serverNames = parser.parseServerNames(extension.payload);
			if (!serverNames.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::SUPPORTED_GROUPS: {
			auto supportedGroups = parser.parseSupportedGroups(extension.payload);
			if (!supportedGroups.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::ELLIPTIC_CURVE_POINT_FORMATS: {
			auto pointFormats
				= parser.parseEllipticCurvePointFormats(extension.payload);
			if (!pointFormats.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::ALPN: {
			auto alpns = parser.parseALPN(extension.payload);
			if (!alpns.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::SIGNATURE_ALGORITHMS: {
			auto signatureAlgorithms = parser.parseSignatureAlgorithms(extension.payload);
			if (!signatureAlgorithms.has_value()) {
				return false;
			}
			break;
		}
		case TLSExtensionType::SUPPORTED_VERSION: {
			auto supportedVersions
				= parser.parseSupportedVersions(extension.payload, *parser.handshake);
			if (!supportedVersions.has_value()) {
				return false;
			}
			break;
		}
		default:
			break;
		}

		return true; });
}

bool parseServerHelloExtensions(TLSParser &parser) noexcept
{
    return parser.parseExtensions([&](const TLSExtension &extension)
                                  {
		if (extension.type == TLSExtensionType::ALPN) {
			const std::optional<TLSParser::ALPNs> alpns = parser.parseALPN(extension.payload);
			if (!alpns.has_value()) {
				return false;
			}
		}

		if (extension.type == TLSExtensionType::SUPPORTED_VERSION) {
			auto supportedVersions
				= parser.parseSupportedVersions(extension.payload, *parser.handshake);
			if (!supportedVersions.has_value()) {
				return false;
			}
		}

		return true; });
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const std::byte *start = reinterpret_cast<const std::byte *>(data);
    std::span<const std::byte> payload_span(start, size);

    TLSParser parser;
    parser.parseHello(payload_span);
    parseClientHelloExtensions(parser);
    parseServerHelloExtensions(parser);

    return 0;
}
