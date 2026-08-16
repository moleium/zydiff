#include "serializer.hpp"
#include <cmath>
#include <cstring>
#include <fstream>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace {

  constexpr uint32_t format_magic = 0x5a594446; // zydf
  constexpr uint32_t format_version = 5;

  class buffer_writer {
public:
    template <typename T>
      requires std::is_trivially_copyable_v<T>
    void write(const T& value) {
      const auto* ptr = reinterpret_cast<const uint8_t*>(&value);
      buffer_.insert(buffer_.end(), ptr, ptr + sizeof(T));
    }

    void write_string(std::string_view str) {
      write(static_cast<uint32_t>(str.size()));
      const auto* ptr = reinterpret_cast<const uint8_t*>(str.data());
      buffer_.insert(buffer_.end(), ptr, ptr + str.size());
    }

    [[nodiscard]] auto save_to_file(const std::string& filepath) const -> bool {
      std::ofstream os(filepath, std::ios::binary);
      if (!os) {
        return false;
      }
      os.write(reinterpret_cast<const char*>(buffer_.data()), static_cast<std::streamsize>(buffer_.size()));
      return os.good();
    }

private:
    std::vector<uint8_t> buffer_;
  };

  class buffer_reader {
public:
    explicit buffer_reader(std::span<const uint8_t> data) : data_(data) {
    }

    template <typename T>
      requires std::is_trivially_copyable_v<T>
    [[nodiscard]] auto read() -> std::optional<T> {
      if (sizeof(T) > data_.size() - offset_) {
        return std::nullopt;
      }
      T value;
      std::memcpy(&value, data_.data() + offset_, sizeof(T));
      offset_ += sizeof(T);
      return value;
    }

    [[nodiscard]] auto read_string() -> std::optional<std::string> {
      auto len = read<uint32_t>();
      if (!len || *len > data_.size() - offset_) {
        return std::nullopt;
      }
      std::string str(reinterpret_cast<const char*>(data_.data() + offset_), *len);
      offset_ += *len;
      return str;
    }

private:
    std::span<const uint8_t> data_;
    size_t offset_{0};
  };

  void write_basic_block(buffer_writer& bw, const subroutine_analyzer::basic_block& bb) {
    bw.write(bb.start_address);
    bw.write(bb.end_address);

    bw.write(static_cast<uint32_t>(bb.successor_keys.size()));
    for (const auto key : bb.successor_keys) {
      bw.write(key);
    }

    bw.write(static_cast<uint32_t>(bb.instruction_keys.size()));
    for (const auto key : bb.instruction_keys) {
      bw.write(key);
    }
    bw.write(static_cast<uint32_t>(bb.match_keys.size()));
    for (const auto key : bb.match_keys) {
      bw.write(key);
    }
    bw.write(bb.match_hash);

    bw.write(static_cast<uint32_t>(bb.instructions.size()));
    for (const auto& instr : bb.instructions) {
      bw.write_string(instr);
    }
  }

  void write_subroutine(buffer_writer& bw, const subroutine_analyzer::subroutine& sub) {
    bw.write(sub.start_address);
    bw.write(sub.end_address);
    bw.write(static_cast<uint64_t>(sub.fingerprint));
    bw.write(static_cast<uint64_t>(sub.byte_size));
    bw.write(static_cast<uint64_t>(sub.instruction_count));
    bw.write(sub.instruction_hash);

    bw.write(static_cast<uint32_t>(sub.basic_blocks.size()));
    for (const auto& bb : sub.basic_blocks) {
      write_basic_block(bw, bb);
    }
  }

  auto read_basic_block(buffer_reader& br) -> std::expected<subroutine_analyzer::basic_block, std::string> {
    subroutine_analyzer::basic_block bb;

    auto start = br.read<uint64_t>();
    auto end = br.read<uint64_t>();
    if (!start || !end) {
      return std::unexpected("corrupt basic_block header");
    }

    bb.start_address = *start;
    bb.end_address = *end;

    auto successor_count = br.read<uint32_t>();
    if (!successor_count) {
      return std::unexpected("corrupt basic_block successor keys");
    }
    bb.successor_keys.reserve(*successor_count);
    for (uint32_t i = 0; i < *successor_count; ++i) {
      auto key = br.read<int64_t>();
      if (!key) {
        return std::unexpected("corrupt basic_block successor key");
      }
      bb.successor_keys.push_back(*key);
    }

    auto key_count = br.read<uint32_t>();
    if (!key_count) {
      return std::unexpected("corrupt basic_block instruction keys");
    }
    bb.instruction_keys.reserve(*key_count);
    for (uint32_t i = 0; i < *key_count; ++i) {
      auto key = br.read<uint64_t>();
      if (!key) {
        return std::unexpected("corrupt basic_block instruction key");
      }
      bb.instruction_keys.push_back(*key);
    }
    auto match_count = br.read<uint32_t>();
    if (!match_count) {
      return std::unexpected("corrupt basic_block match keys");
    }
    bb.match_keys.reserve(*match_count);
    for (uint32_t i = 0; i < *match_count; ++i) {
      auto key = br.read<uint64_t>();
      if (!key) {
        return std::unexpected("corrupt basic_block match key");
      }
      bb.match_keys.push_back(*key);
    }
    auto match_hash = br.read<uint64_t>();
    if (!match_hash) {
      return std::unexpected("corrupt basic_block match hash");
    }
    bb.match_hash = *match_hash;

    auto inst_count = br.read<uint32_t>();
    if (!inst_count) {
      return std::unexpected("corrupt basic_block instruction count");
    }

    bb.instructions.reserve(*inst_count);
    for (uint32_t i = 0; i < *inst_count; ++i) {
      auto inst = br.read_string();
      if (!inst) {
        return std::unexpected("corrupt basic_block instruction");
      }
      bb.instructions.push_back(std::move(*inst));
    }

    return bb;
  }

  auto read_subroutine(buffer_reader& br) -> std::expected<subroutine_analyzer::subroutine, std::string> {
    subroutine_analyzer::subroutine sub;

    auto start = br.read<uint64_t>();
    auto end = br.read<uint64_t>();
    auto fp = br.read<uint64_t>();
    auto byte_size = br.read<uint64_t>();
    auto instruction_count = br.read<uint64_t>();
    auto instruction_hash = br.read<uint64_t>();
    auto bb_count = br.read<uint32_t>();

    if (!start || !end || !fp || !byte_size || !instruction_count || !instruction_hash || !bb_count) {
      return std::unexpected("corrupt subroutine header");
    }

    sub.start_address = *start;
    sub.end_address = *end;
    sub.fingerprint = static_cast<fingerprint>(*fp);
    sub.byte_size = static_cast<size_t>(*byte_size);
    sub.instruction_count = static_cast<size_t>(*instruction_count);
    sub.instruction_hash = *instruction_hash;

    sub.basic_blocks.reserve(*bb_count);
    for (uint32_t i = 0; i < *bb_count; ++i) {
      auto bb = read_basic_block(br);
      if (!bb) {
        return std::unexpected(bb.error());
      }
      sub.basic_blocks.push_back(std::move(*bb));
    }

    return sub;
  }

} // namespace

auto diff_serializer::save(const binary_differ::diff_result& result, const std::string& filepath) -> bool {
  buffer_writer bw;

  bw.write(format_magic);
  bw.write(format_version);
  bw.write(static_cast<uint64_t>(result.primary_count));
  bw.write(static_cast<uint64_t>(result.secondary_count));
  bw.write(static_cast<uint64_t>(result.skipped_candidates));

  bw.write(static_cast<uint32_t>(result.matches.size()));
  for (const auto& match : result.matches) {
    write_subroutine(bw, match.primary);
    write_subroutine(bw, match.secondary);
    bw.write(match.change);
    bw.write(match.similarity);
  }

  bw.write(static_cast<uint32_t>(result.unmatched_primary.size()));
  for (const auto& sub : result.unmatched_primary) {
    write_subroutine(bw, sub);
  }

  bw.write(static_cast<uint32_t>(result.unmatched_secondary.size()));
  for (const auto& sub : result.unmatched_secondary) {
    write_subroutine(bw, sub);
  }

  return bw.save_to_file(filepath);
}

auto diff_serializer::load(const std::string& filepath) -> std::expected<binary_differ::diff_result, std::string> {
  std::ifstream is(filepath, std::ios::binary | std::ios::ate);
  if (!is) {
    return std::unexpected("failed to open file");
  }

  auto size = is.tellg();
  if (size < 8) {
    return std::unexpected("file too small to contain valid header");
  }

  is.seekg(0, std::ios::beg);
  std::vector<uint8_t> buffer(static_cast<size_t>(size));
  if (!is.read(reinterpret_cast<char*>(buffer.data()), size)) {
    return std::unexpected("failed to read file content");
  }

  buffer_reader br(buffer);

  auto magic = br.read<uint32_t>();
  auto version = br.read<uint32_t>();

  if (!magic || *magic != format_magic) {
    return std::unexpected("invalid file magic");
  }
  if (!version || *version != format_version) {
    return std::unexpected("unsupported format version");
  }

  binary_differ::diff_result result;
  auto primary_count = br.read<uint64_t>();
  auto secondary_count = br.read<uint64_t>();
  auto skipped_candidates = br.read<uint64_t>();
  if (!primary_count || !secondary_count || !skipped_candidates) {
    return std::unexpected("corrupt result counts");
  }
  result.primary_count = static_cast<size_t>(*primary_count);
  result.secondary_count = static_cast<size_t>(*secondary_count);
  result.skipped_candidates = static_cast<size_t>(*skipped_candidates);

  auto match_count = br.read<uint32_t>();
  if (!match_count) {
    return std::unexpected("corrupt matches count");
  }

  result.matches.reserve(*match_count);
  for (uint32_t i = 0; i < *match_count; ++i) {
    auto p = read_subroutine(br);
    if (!p)
      return std::unexpected(p.error());

    auto s = read_subroutine(br);
    if (!s)
      return std::unexpected(s.error());

    auto change = br.read<binary_differ::change_type>();
    auto similarity = br.read<double>();
    if (!change || !similarity) {
      return std::unexpected("corrupt match metadata");
    }
    if (
      *change > binary_differ::change_type::instructions_changed || !std::isfinite(*similarity) || *similarity < 0.0 ||
      *similarity > 1.0
    ) {
      return std::unexpected("invalid match metadata");
    }
    result.matches.push_back({
      .primary = std::move(*p),
      .secondary = std::move(*s),
      .change = *change,
      .similarity = *similarity,
    });
  }

  auto up_count = br.read<uint32_t>();
  if (!up_count) {
    return std::unexpected("corrupt unmatched primary count");
  }

  result.unmatched_primary.reserve(*up_count);
  for (uint32_t i = 0; i < *up_count; ++i) {
    auto sub = read_subroutine(br);
    if (!sub)
      return std::unexpected(sub.error());
    result.unmatched_primary.push_back(std::move(*sub));
  }

  auto us_count = br.read<uint32_t>();
  if (!us_count) {
    return std::unexpected("corrupt unmatched secondary count");
  }

  result.unmatched_secondary.reserve(*us_count);
  for (uint32_t i = 0; i < *us_count; ++i) {
    auto sub = read_subroutine(br);
    if (!sub)
      return std::unexpected(sub.error());
    result.unmatched_secondary.push_back(std::move(*sub));
  }

  return result;
}
