#include "HidraFersDecoder2.hh"
#include "HidraUtils.hh"

#include <cstdint>
#include <cstring>
#include <vector>

namespace hidra {

namespace {

// ---------------------------------------------------------------------------
// On-wire layout, taken directly from the producer (HidraFERS2Producer) and the
// CAEN SpectEvent_t struct. All multi-byte fields are little-endian; on the x86
// DAQ host that matches the native byte order, so a plain memcpy-based read is a
// little-endian read (consistent with the rest of HiDRA, which assumes LE).
//
// Per-board block written by the producer:
//   [0]  uint16  marker          (0xAAAA)
//   [2]  uint16  block_size       (full block length in bytes, header included)
//   [4]  uint32  data_qualifier
//   [8]  uint8   board_id
//   [9]  ...     vendor event struct (raw native copy)
// ---------------------------------------------------------------------------

constexpr std::size_t kHeaderSize = 9;
constexpr std::uint16_t kBoardMarker = 0xAAAA;

constexpr std::size_t kOffMarker = 0;
constexpr std::size_t kOffBlockSize = 2;
constexpr std::size_t kOffDataQualifier = 4;
constexpr std::size_t kOffBoardId = 8;

// CAEN data qualifiers (FERSlib.h); the base mode is the low nibble. The producer
// recognises spectroscopy as `(dq & 0x0F) == DTQ_SPECT || dq == DTQ_TSPECT`.
constexpr std::uint32_t kDtqBaseMask = 0x0F;
constexpr std::uint32_t kDtqSpect = 0x01;  // Spectroscopy (energy)
constexpr std::uint32_t kDtqTSpect = 0x03; // Spectroscopy + timing

// SpectEvent_t layout (offsets relative to the start of the vendor struct, i.e.
// kHeaderSize). Matches fers2/README.md and DataFormat.md (v7/v8): 696 bytes.
//   double   tstamp_us       @0
//   double   rel_tstamp_us   @8
//   uint64   tstamp_clk      @16   (unused here)
//   uint64   Tref_tstamp     @24   (unused here)
//   uint64   trigger_id      @32
//   uint64   chmask          @40
//   uint64   qdmask          @48   (available; see note below)
//   uint16   energyHG[64]    @56
//   uint16   energyLG[64]    @184
//   uint32   tstamp[64]/ToA  @312
//   uint16   ToT[64]         @568
constexpr std::size_t kSpectVendorSize = 696;
constexpr std::size_t kSpectBlockSize = kHeaderSize + kSpectVendorSize; // 705

constexpr std::size_t kOffTstampUs = kHeaderSize + 0;
constexpr std::size_t kOffRelTstampUs = kHeaderSize + 8;
constexpr std::size_t kOffTriggerId = kHeaderSize + 32;
constexpr std::size_t kOffChMask = kHeaderSize + 40;
constexpr std::size_t kOffQdMask = kHeaderSize + 48;
constexpr std::size_t kOffEnergyHG = kHeaderSize + 56;
constexpr std::size_t kOffEnergyLG = kHeaderSize + 184;
constexpr std::size_t kOffToA = kHeaderSize + 312;
constexpr std::size_t kOffToT = kHeaderSize + 568;

constexpr int kChannelsPerBoard = 64;
constexpr int kMaxBoards = 20;
constexpr int kMaxChannels = kChannelsPerBoard * kMaxBoards; // 1280

// Read a little-endian POD field at `offset`. The caller guarantees that
// [offset, offset + sizeof(T)) lies inside a validated block.
template <typename T> T ReadLE(const std::uint8_t* data, std::size_t offset) {
  T value{};
  std::memcpy(&value, data + offset, sizeof(T));
  return value;
}

} // namespace

void HidraFersDecoder2::decode(const std::vector<std::uint8_t>& payload, HidraFersEvent& event) const {
  static_assert(kSpectBlockSize == 705, "FERS spectroscopy block size changed; review the offsets above");
  static_assert(kOffToT + 2 * kChannelsPerBoard == kSpectBlockSize, "SpectEvent_t offsets do not add up to the block size");

  // Start from an all-sentinel event so disabled channels / absent boards read -1.
  event = HidraFersEvent{};
  event.FERStsamp_us.assign(kMaxChannels, -1.0);
  event.FERSrel_tsamp_us.assign(kMaxChannels, -1.0);
  event.FERStrigger_id.assign(kMaxChannels, -1.0);
  event.FERSboard_id.assign(kMaxChannels, -1.0);
  event.FERShg.assign(kMaxChannels, -1.0);
  event.FERSlg.assign(kMaxChannels, -1.0);
  event.FERStoa.assign(kMaxChannels, -1.0);
  event.FERStot.assign(kMaxChannels, -1.0);

  if (payload.empty()) {
    HIDRA_ERROR("FERS payload is empty. Nothing to decode");
    return;
  }

  const std::uint8_t* data = payload.data();
  const std::size_t size = payload.size();

  bool stopped_on_error = false;
  std::size_t pos = 0;

  while (pos + kHeaderSize <= size) {
    const std::uint16_t marker = ReadLE<std::uint16_t>(data, pos + kOffMarker);
    if (marker != kBoardMarker) {
      HIDRA_ERROR("FERS: bad board marker {:04X} at offset {} (expected {:04X}). Stopping decode",
                  marker,
                  pos,
                  kBoardMarker);
      stopped_on_error = true;
      break;
    }

    const std::uint16_t block_size = ReadLE<std::uint16_t>(data, pos + kOffBlockSize);
    const std::uint32_t data_qualifier = ReadLE<std::uint32_t>(data, pos + kOffDataQualifier);
    const std::uint8_t board_id = ReadLE<std::uint8_t>(data, pos + kOffBoardId);

    if (block_size < kHeaderSize || pos + block_size > size) {
      HIDRA_ERROR("FERS: invalid block_size {} at offset {} (payload is {} bytes). Stopping decode",
                  block_size,
                  pos,
                  size);
      stopped_on_error = true;
      break;
    }

    const std::uint32_t base_dq = data_qualifier & kDtqBaseMask;
    const bool is_spect = (base_dq == kDtqSpect) || (data_qualifier == kDtqTSpect);
    if (!is_spect) {
      // A timing/counting/service block has a different size and layout; this decoder
      // only fills the spectroscopy fields of HidraFersEvent, so skip it cleanly.
      HIDRA_DEBUG("FERS: skipping non-spectroscopy block (dq={:08X}) at offset {}", data_qualifier, pos);
      pos += block_size;
      continue;
    }

    if (block_size != kSpectBlockSize) {
      HIDRA_ERROR("FERS: spectroscopy block has size {} (expected {}) at offset {}. Skipping block",
                  block_size,
                  kSpectBlockSize,
                  pos);
      pos += block_size;
      continue;
    }

    if (board_id >= kMaxBoards) {
      HIDRA_ERROR("FERS: invalid board_id {} at offset {}. Skipping block", board_id, pos);
      pos += block_size;
      continue;
    }

    const double tstamp_us = ReadLE<double>(data, pos + kOffTstampUs);
    const double rel_tstamp_us = ReadLE<double>(data, pos + kOffRelTstampUs);
    const std::uint64_t trigger_id = ReadLE<std::uint64_t>(data, pos + kOffTriggerId);
    const std::uint64_t chmask = ReadLE<std::uint64_t>(data, pos + kOffChMask);
    // qdmask (per-channel charge validity) is at kOffQdMask. It is intentionally not
    // applied here because HidraFersEvent has no per-channel validity field; expose it
    // there first if charge-validity filtering is wanted.

    for (int ich = 0; ich < kChannelsPerBoard; ++ich) {
      if (((chmask >> ich) & 0x1ULL) == 0ULL) {
        continue; // channel disabled in chmask: keep the -1 sentinel
      }

      const int index = board_id * kChannelsPerBoard + ich;
      event.FERStsamp_us[index] = tstamp_us;
      event.FERSrel_tsamp_us[index] = rel_tstamp_us;
      event.FERStrigger_id[index] = static_cast<double>(trigger_id);
      event.FERSboard_id[index] = static_cast<double>(board_id);
      event.FERShg[index] = static_cast<double>(ReadLE<std::uint16_t>(data, pos + kOffEnergyHG + 2 * ich));
      event.FERSlg[index] = static_cast<double>(ReadLE<std::uint16_t>(data, pos + kOffEnergyLG + 2 * ich));
      event.FERStoa[index] = static_cast<double>(ReadLE<std::uint32_t>(data, pos + kOffToA + 4 * ich));
      event.FERStot[index] = static_cast<double>(ReadLE<std::uint16_t>(data, pos + kOffToT + 2 * ich));
    }

    pos += block_size;
  }

  if (!stopped_on_error && pos != size) {
    HIDRA_WARN("FERS: {} trailing byte(s) after the last complete block (offset {} of {})", size - pos, pos, size);
  }
}

} // namespace hidra
