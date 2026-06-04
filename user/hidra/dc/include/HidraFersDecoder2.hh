#pragma once

#include "HidraFersEvent.hh"

#include <cstdint>
#include <vector>

namespace hidra {

/**
 * @brief Proposed rewrite of HidraFersDecoder, written from the producer side.
 *
 * Differences from the original HidraFersDecoder (and the rationale, tracked in the
 * decoder review issues):
 *
 *  - Reads every field by explicit little-endian offset via ReadLE() instead of
 *    `memcpy`-ing the buffer into a `#pragma pack` mirror struct. This removes the
 *    hand-maintained struct that can silently drift from the vendor `SpectEvent_t`
 *    layout (issue #128) and the misaligned-access UB of dereferencing a packed
 *    struct (issue #84).
 *  - Walks the payload block-by-block using the producer framing: it validates the
 *    per-board `marker` (0xAAAA) and advances by the per-board `block_size` instead of
 *    assuming a uniform 705-byte stream, so misalignment/corruption is detected rather
 *    than silently misdecoded (issue #127).
 *  - Inspects the per-board `data_qualifier` and only decodes spectroscopy
 *    (DTQ_SPECT / DTQ_TSPECT) blocks; other event types are skipped instead of being
 *    reinterpreted as spectroscopy (issue #127).
 *  - Honours `chmask` per channel: enabled channels are filled, disabled channels keep
 *    the -1 sentinel, instead of dropping the whole board when not all 64 channels are
 *    enabled (issue #129).
 *
 * The interface is kept identical to HidraFersDecoder (takes the EUDAQ detector payload
 * as a byte vector and fills a HidraFersEvent) so it can be a drop-in replacement: to
 * adopt it, rename the class to HidraFersDecoder, swap the files, and keep the existing
 * call site in HidraRootPayloadDecoders unchanged.
 */
class HidraFersDecoder2 {
public:
  void decode(const std::vector<std::uint8_t>& payload, HidraFersEvent& event) const;
};

} // namespace hidra
