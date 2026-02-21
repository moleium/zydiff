#include "serializer.hpp"
#include <cstring>
#include <fstream>
#include <span>
#include <vector>

namespace {

constexpr uint32_t format_magic = 0x5a594446; // zydf
constexpr uint32_t format_version = 1;

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
  explicit buffer_reader(std::span<const uint8_t> data) : data_(data) {}

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

  bw.write(static_cast<uint32_t>(bb.successors.size()));
  for (auto succ : bb.successors) {
    bw.write(succ);
  }

  bw.write(static_cast<uint32_t>(bb.instructions.size()));
  for (const auto& instr : bb.instructions) {
    bw.write_string(instr);
  }
}

void write_subroutine(buffer_writer& bw, const subroutine_analyzer::subroutine& sub) {
  bw.write(sub.start_address);
  bw.write(sub.end_address);
  bw.write(static_cast<uint64_t>(sub.fingerprint));
  bw.write(sub.similarity_score);

  bw.write(static_cast<uint32_t>(sub.basic_blocks.size()));
  for (const auto& bb : sub.basic_blocks) {
    write_basic_block(bw, bb);
  }

  bw.write(static_cast<uint32_t>(sub.diff_details.size()));
  for (const auto& detail : sub.diff_details) {
    bw.write_string(detail);
  }
}

auto read_basic_block(buffer_reader& br) -> std::expected<subroutine_analyzer::basic_block, std::string> {
  subroutine_analyzer::basic_block bb;

  auto start = br.read<uint64_t>();
  auto end = br.read<uint64_t>();
  auto succ_count = br.read<uint32_t>();
  if (!start || !end || !succ_count) {
    return std::unexpected("corrupt basic_block header");
  }

  bb.start_address = *start;
  bb.end_address = *end;

  bb.successors.reserve(*succ_count);
  for (uint32_t i = 0; i < *succ_count; ++i) {
    auto succ = br.read<uint64_t>();
    if (!succ) {
      return std::unexpected("corrupt basic_block successor");
    }
    bb.successors.push_back(*succ);
  }

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
  auto sim = br.read<double>();
  auto bb_count = br.read<uint32_t>();

  if (!start || !end || !fp || !sim || !bb_count) {
    return std::unexpected("corrupt subroutine header");
  }

  sub.start_address = *start;
  sub.end_address = *end;
  sub.fingerprint = static_cast<fingerprint>(*fp);
  sub.similarity_score = *sim;

  sub.basic_blocks.reserve(*bb_count);
  for (uint32_t i = 0; i < *bb_count; ++i) {
    auto bb = read_basic_block(br);
    if (!bb) {
      return std::unexpected(bb.error());
    }
    sub.basic_blocks.push_back(std::move(*bb));
  }

  auto diff_count = br.read<uint32_t>();
  if (!diff_count) {
    return std::unexpected("corrupt subroutine diff details count");
  }

  sub.diff_details.reserve(*diff_count);
  for (uint32_t i = 0; i < *diff_count; ++i) {
    auto detail = br.read_string();
    if (!detail) {
      return std::unexpected("corrupt subroutine diff detail");
    }
    sub.diff_details.push_back(std::move(*detail));
  }

  return sub;
}

} // namespace

auto diff_serializer::save(const binary_differ::diff_result& result, const std::string& filepath) -> bool {
  buffer_writer bw;

  bw.write(format_magic);
  bw.write(format_version);

  bw.write(static_cast<uint32_t>(result.matched_subroutines.size()));
  for (const auto& [p, s] : result.matched_subroutines) {
    write_subroutine(bw, p);
    write_subroutine(bw, s);
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

  auto match_count = br.read<uint32_t>();
  if (!match_count) {
    return std::unexpected("corrupt matches count");
  }

  result.matched_subroutines.reserve(*match_count);
  for (uint32_t i = 0; i < *match_count; ++i) {
    auto p = read_subroutine(br);
    if (!p) return std::unexpected(p.error());

    auto s = read_subroutine(br);
    if (!s) return std::unexpected(s.error());

    result.matched_subroutines.emplace_back(std::move(*p), std::move(*s));
  }

  auto up_count = br.read<uint32_t>();
  if (!up_count) {
    return std::unexpected("corrupt unmatched primary count");
  }

  result.unmatched_primary.reserve(*up_count);
  for (uint32_t i = 0; i < *up_count; ++i) {
    auto sub = read_subroutine(br);
    if (!sub) return std::unexpected(sub.error());
    result.unmatched_primary.push_back(std::move(*sub));
  }

  auto us_count = br.read<uint32_t>();
  if (!us_count) {
    return std::unexpected("corrupt unmatched secondary count");
  }

  result.unmatched_secondary.reserve(*us_count);
  for (uint32_t i = 0; i < *us_count; ++i) {
    auto sub = read_subroutine(br);
    if (!sub) return std::unexpected(sub.error());
    result.unmatched_secondary.push_back(std::move(*sub));
  }

  return result;
}
