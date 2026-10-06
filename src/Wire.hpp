#pragma once

// Binary wire format primitives: "the struct is the wire layout".
//
// Every fixed-size on-disk record is a plain struct (no #pragma pack) whose members are only
// uint8_t/char arrays, the endian field types below (be16/be32/be64, le16/le32/le64, be24/le24)
// or other wire structs. Each of those has alignof 1, so sizeof and offsetof are the on-disk size
// and offsets, and the struct holds its fields in on-disk byte order. Fields read as host integers
// (implicit conversion or .get()) and assign from host integers (operator= or .set()).
//
// Bytes enter and leave a record only through read, read_head, write, patch, append, encode,
// bytes_of or Cursor::take. A record is a lossless codec: nothing here validates or normalises
// a value, so ciphertext headers survive a read followed by a write unchanged.
//
// Every bounds check has the form `offset > size || size - offset < n`, so it cannot wrap. A short
// read fails with ErrorCode::Truncated and a short write with ErrorCode::OutOfRange; the message
// names the record (`what`) and the offset. The caller adds its own context with with_context()
// and never logs the error (src/Error.hpp policy).
//
// Assignment from a wider type narrows silently (-Wconversion is off): cast explicitly, as in
// `h.size = static_cast<uint32_t>(n);`. `auto x = h.size` yields a be32, not a host integer; use a
// typed local or .get(), and use .get() before passing a field to a deduced template such as
// std::max. A manual bswap16/32/64 or swap32 on a field is a compile error (deleted overloads at
// the end of this header), as is std::byteswap, compound assignment and `be32 v = 5u`.
//
// This header is std-only (plus Error.hpp) on purpose so any internal header can include it.

#include "Error.hpp"

#include <array>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <span>
#include <string_view>
#include <type_traits>
#include <vector>

namespace gxbuild3::wire {

    static_assert(std::endian::native == std::endian::little ||
                      std::endian::native == std::endian::big,
                  "mixed-endian hosts are not supported");

    namespace detail {

        // Decodes N bytes stored in byte order E. Independent of the host byte order.
        template <std::unsigned_integral T, std::endian E, std::size_t N>
        [[nodiscard]] constexpr T load(const std::array<std::uint8_t, N>& bytes) noexcept {
            T value = 0;
            for (std::size_t i = 0; i < N; ++i) {
                const std::size_t index = E == std::endian::big ? i : N - 1 - i;
                value = static_cast<T>((value << 8) | bytes[index]);
            }
            return value;
        }

        // Encodes the low N bytes of value in byte order E.
        template <std::unsigned_integral T, std::endian E, std::size_t N>
        constexpr void store(std::array<std::uint8_t, N>& bytes, T value) noexcept {
            for (std::size_t i = 0; i < N; ++i) {
                const std::size_t index = E == std::endian::big ? N - 1 - i : i;
                bytes[index] = static_cast<std::uint8_t>(value & 0xFFU);
                value = static_cast<T>(value >> 8);
            }
        }

        // True when n bytes fit at offset inside size bytes; written so it cannot wrap.
        [[nodiscard]] constexpr bool fits(std::size_t size, std::size_t offset,
                                          std::size_t n) noexcept {
            return offset <= size && size - offset >= n;
        }

        [[nodiscard]] constexpr std::size_t available(std::size_t size,
                                                      std::size_t offset) noexcept {
            return offset > size ? 0 : size - offset;
        }

        // `at` is the absolute offset reported to the user; `left` the bytes available there.
        [[nodiscard]] inline std::unexpected<Error>
        short_read(std::string_view what, std::size_t need, std::size_t at, std::size_t left) {
            return fail(ErrorCode::Truncated,
                        "{}: need {:#x} bytes at offset {:#x}, {:#x} available", what, need, at,
                        left);
        }

        [[nodiscard]] inline std::unexpected<Error>
        short_write(std::string_view what, std::size_t need, std::size_t at, std::size_t left) {
            return fail(ErrorCode::OutOfRange,
                        "{}: cannot write {:#x} bytes at offset {:#x}, {:#x} available", what, need,
                        at, left);
        }

    } // namespace detail

    // An unsigned integer of type T stored in byte order E, with alignment 1.
    template <std::unsigned_integral T, std::endian E> class endian_int {
      public:
        using value_type = T;
        static constexpr std::endian byte_order = E;

        // Trivial: `X x{};` zero-fills, `X x;` is uninitialised like any scalar.
        endian_int() noexcept = default;
        // Explicit so `c ? h.f : 0xFF4F` stays unambiguous and `be32 v = 5u;` does not compile.
        constexpr explicit endian_int(T value) noexcept { set(value); }

        constexpr endian_int& operator=(T value) noexcept {
            set(value);
            return *this;
        }

        [[nodiscard]] constexpr T get() const noexcept { return detail::load<T, E>(m_bytes); }

        constexpr void set(T value) noexcept { detail::store<T, E>(m_bytes, value); }

        // Implicit so ==, <, &, switch and arithmetic read the host value.
        constexpr operator T() const noexcept { return get(); }

        // The stored bytes, in on-disk order.
        [[nodiscard]] constexpr const std::array<std::uint8_t, sizeof(T)>& raw() const noexcept {
            return m_bytes;
        }

      private:
        std::array<std::uint8_t, sizeof(T)> m_bytes;
    };

    using be16 = endian_int<std::uint16_t, std::endian::big>;
    using be32 = endian_int<std::uint32_t, std::endian::big>;
    using be64 = endian_int<std::uint64_t, std::endian::big>;
    using le16 = endian_int<std::uint16_t, std::endian::little>;
    using le32 = endian_int<std::uint32_t, std::endian::little>;
    using le64 = endian_int<std::uint64_t, std::endian::little>;

    // A 24-bit unsigned integer stored in byte order E (STFS block numbers and table fields).
    // Same surface as endian_int with a uint32_t host value; set() keeps the low 24 bits.
    template <std::endian E> class uint24 {
      public:
        using value_type = std::uint32_t;
        static constexpr std::endian byte_order = E;
        static constexpr std::uint32_t max = 0xFFFFFFU;

        uint24() noexcept = default;
        constexpr explicit uint24(std::uint32_t value) noexcept { set(value); }

        constexpr uint24& operator=(std::uint32_t value) noexcept {
            set(value);
            return *this;
        }

        [[nodiscard]] constexpr std::uint32_t get() const noexcept {
            return detail::load<std::uint32_t, E>(m_bytes);
        }

        constexpr void set(std::uint32_t value) noexcept {
            detail::store<std::uint32_t, E>(m_bytes, value & max);
        }

        constexpr operator std::uint32_t() const noexcept { return get(); }

        [[nodiscard]] constexpr const std::array<std::uint8_t, 3>& raw() const noexcept {
            return m_bytes;
        }

      private:
        std::array<std::uint8_t, 3> m_bytes;
    };

    using be24 = uint24<std::endian::big>;
    using le24 = uint24<std::endian::little>;

    static_assert(sizeof(be16) == 2 && sizeof(be32) == 4 && sizeof(be64) == 8 && sizeof(be24) == 3);
    static_assert(alignof(be16) == 1 && alignof(be32) == 1 && alignof(be64) == 1 &&
                  alignof(be24) == 1);

    // fmt (spdlog) finds these by ADL; std::format uses the std::formatter specialisations at the
    // end of this header.
    template <class T, std::endian E> constexpr T format_as(endian_int<T, E> value) noexcept {
        return value.get();
    }

    template <std::endian E> constexpr std::uint32_t format_as(uint24<E> value) noexcept {
        return value.get();
    }

    // A type whose object representation is its on-disk image.
    template <class T>
    concept WireLayout = std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T> &&
                         alignof(T) == 1 && std::has_unique_object_representations_v<T>;

    static_assert(WireLayout<be16> && WireLayout<be32> && WireLayout<be64> && WireLayout<le16> &&
                  WireLayout<le32> && WireLayout<le64> && WireLayout<be24> && WireLayout<le24>);

    // ---- Records -------------------------------------------------------------------------------

    // Reads a T at offset. Fails with Truncated when it does not fit.
    template <WireLayout T>
    [[nodiscard]] Result<T> read(std::span<const std::uint8_t> bytes, std::size_t offset,
                                 std::string_view what) {
        if (!detail::fits(bytes.size(), offset, sizeof(T))) {
            return detail::short_read(what, sizeof(T), offset,
                                      detail::available(bytes.size(), offset));
        }
        std::array<std::uint8_t, sizeof(T)> image;
        std::memcpy(image.data(), bytes.data() + offset, sizeof(T));
        return std::bit_cast<T>(image);
    }

    // A record read from the front of a span, plus the bytes after it. `rest` borrows the
    // caller's storage.
    template <WireLayout T> struct Head {
        T value;
        std::span<const std::uint8_t> rest;
    };

    template <WireLayout T>
    [[nodiscard]] Result<Head<T>> read_head(std::span<const std::uint8_t> bytes,
                                            std::string_view what) {
        auto value = read<T>(bytes, 0, what);
        if (!value) {
            return std::unexpected(std::move(value.error()));
        }
        return Head<T>{*value, bytes.subspan(sizeof(T))};
    }

    // Writes value at offset. Fails with OutOfRange when it does not fit; out is then untouched.
    template <WireLayout T>
    [[nodiscard]] Result<void> write(std::span<std::uint8_t> out, std::size_t offset,
                                     const T& value, std::string_view what) {
        if (!detail::fits(out.size(), offset, sizeof(T))) {
            return detail::short_write(what, sizeof(T), offset,
                                       detail::available(out.size(), offset));
        }
        std::memcpy(out.data() + offset, &value, sizeof(T));
        return {};
    }

    // Read-modify-write of the T at offset: edit(T&) changes the decoded record and the result is
    // written back. Fails with Truncated (edit is not called) when the record does not fit.
    template <WireLayout T, std::invocable<T&> Edit>
    [[nodiscard]] Result<void> patch(std::span<std::uint8_t> bytes, std::size_t offset,
                                     std::string_view what, Edit&& edit) {
        // The bounds check sits beside the write-back so the compiler sees the store guarded.
        if (!detail::fits(bytes.size(), offset, sizeof(T))) {
            return detail::short_read(what, sizeof(T), offset,
                                      detail::available(bytes.size(), offset));
        }
        std::array<std::uint8_t, sizeof(T)> image;
        std::memcpy(image.data(), bytes.data() + offset, sizeof(T));
        T value = std::bit_cast<T>(image);
        std::forward<Edit>(edit)(value);
        image = std::bit_cast<std::array<std::uint8_t, sizeof(T)>>(value);
        std::memcpy(bytes.data() + offset, image.data(), sizeof(T));
        return {};
    }

    // The on-disk image of value.
    template <WireLayout T>
    [[nodiscard]] constexpr std::array<std::uint8_t, sizeof(T)> encode(const T& value) noexcept {
        return std::bit_cast<std::array<std::uint8_t, sizeof(T)>>(value);
    }

    template <WireLayout T> void append(std::vector<std::uint8_t>& out, const T& value) {
        const auto image = encode(value);
        const std::size_t at = out.size();
        out.resize(at + sizeof(T));
        std::memcpy(out.data() + at, image.data(), sizeof(T));
    }

    // A view of value's bytes; valid as long as value is.
    template <WireLayout T>
    [[nodiscard]] std::span<const std::uint8_t, sizeof(T)> bytes_of(const T& value) noexcept {
        return std::span<const std::uint8_t, sizeof(T)>(
            reinterpret_cast<const std::uint8_t*>(&value), sizeof(T));
    }

    // Views std::byte storage (STFS buffers) as the uint8_t spans the functions above take.
    [[nodiscard]] inline std::span<const std::uint8_t>
    as_u8(std::span<const std::byte> bytes) noexcept {
        return {reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()};
    }

    // ---- Streams -------------------------------------------------------------------------------

    // A forward reader over variable-length data. Every take is checked and returns a Result;
    // there is no sticky state: a failed take leaves the position unchanged and later takes are
    // checked on their own. Error messages give the absolute offset, base + position. Spans the
    // cursor hands out borrow the caller's storage.
    class Cursor {
      public:
        constexpr explicit Cursor(std::span<const std::uint8_t> bytes,
                                  std::size_t base = 0) noexcept
            : m_bytes(bytes), m_base(base) {}

        // Absolute offset of the next byte: base + position.
        [[nodiscard]] constexpr std::size_t offset() const noexcept { return m_base + m_position; }
        [[nodiscard]] constexpr std::size_t remaining() const noexcept {
            return m_bytes.size() - m_position;
        }
        [[nodiscard]] constexpr bool at_end() const noexcept { return remaining() == 0; }

        template <WireLayout T> [[nodiscard]] Result<T> take(std::string_view what) {
            if (remaining() < sizeof(T)) {
                return detail::short_read(what, sizeof(T), offset(), remaining());
            }
            auto value = read<T>(m_bytes, m_position, what);
            m_position += sizeof(T);
            return value;
        }

        [[nodiscard]] Result<std::span<const std::uint8_t>> take_bytes(std::size_t n,
                                                                       std::string_view what) {
            if (remaining() < n) {
                return detail::short_read(what, n, offset(), remaining());
            }
            const auto bytes = m_bytes.subspan(m_position, n);
            m_position += n;
            return bytes;
        }

        [[nodiscard]] Result<void> skip(std::size_t n, std::string_view what) {
            if (remaining() < n) {
                return detail::short_read(what, n, offset(), remaining());
            }
            m_position += n;
            return {};
        }

        // A cursor over the next n bytes, based at their absolute offset; this cursor advances
        // past them.
        [[nodiscard]] Result<Cursor> sub(std::size_t n, std::string_view what) {
            const std::size_t start = offset();
            auto bytes = take_bytes(n, what);
            if (!bytes) {
                return std::unexpected(std::move(bytes.error()));
            }
            return Cursor(*bytes, start);
        }

        // The bytes taken so far: [0, position).
        [[nodiscard]] std::span<const std::uint8_t> consumed() const noexcept {
            return m_bytes.first(m_position);
        }

      private:
        std::span<const std::uint8_t> m_bytes;
        std::size_t m_base = 0;
        std::size_t m_position = 0;
    };

} // namespace gxbuild3::wire

namespace std {

    template <class T, std::endian E, class CharT>
    struct formatter<gxbuild3::wire::endian_int<T, E>, CharT> : formatter<T, CharT> {
        template <class FormatContext>
        auto format(gxbuild3::wire::endian_int<T, E> value, FormatContext& context) const {
            return formatter<T, CharT>::format(value.get(), context);
        }
    };

    template <std::endian E, class CharT>
    struct formatter<gxbuild3::wire::uint24<E>, CharT> : formatter<std::uint32_t, CharT> {
        template <class FormatContext>
        auto format(gxbuild3::wire::uint24<E> value, FormatContext& context) const {
            return formatter<std::uint32_t, CharT>::format(value.get(), context);
        }
    };

} // namespace std

namespace gxbuild3 {

    // A leftover manual swap on a wire field is a compile error, not a silent double swap. These
    // win overload resolution over the uint*_t helpers in Endian.hpp (exact match versus a
    // user-defined conversion).
    template <class T, std::endian E> void bswap16(wire::endian_int<T, E>) = delete;
    template <class T, std::endian E> void bswap32(wire::endian_int<T, E>) = delete;
    template <class T, std::endian E> void bswap64(wire::endian_int<T, E>) = delete;
    template <class T, std::endian E> void swap32(wire::endian_int<T, E>) = delete;
    template <std::endian E> void bswap32(wire::uint24<E>) = delete;
    template <std::endian E> void swap32(wire::uint24<E>) = delete;

} // namespace gxbuild3
