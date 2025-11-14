#include <cstddef>
#include <cstdint>
#include <vector>
#include "../ipfixprobe/src/plugins/process/quic/src/quicParser.hpp"

using namespace ipxp::process::quic;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const std::byte *start = reinterpret_cast<const std::byte *>(data);
	std::span<const std::byte> payload_span(start + 1, size - 1);

	if (size < 1)
	{
		return 0;
	}

	const uint8_t l4_protocol = *(reinterpret_cast<const uint8_t *>(data));

	QUICParser parser;
	parser.parse(payload_span, std::nullopt, l4_protocol);

	return 0;
}
