// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_UTILITY_BYTE_HPP
#define BOOST_CRYPT_UTILITY_BYTE_HPP

#include <boost/crypt/utility/concepts.hpp>
#include <type_traits>
#include <cstdint>

namespace boost {
namespace crypt {

class byte
{
private:
    std::uint8_t bits_;

public:
    constexpr byte() noexcept : bits_ {} {}
    explicit constexpr byte(std::uint8_t bits) noexcept : bits_ {bits} {}

    template <typename IntegerType>
    constexpr auto to_integer() noexcept -> IntegerType
    {
        return static_cast<IntegerType>(bits_);
    }

    template <typename IntegerType>
    constexpr auto operator<<(IntegerType shift) noexcept -> byte
    {
        return byte{bits_ << shift};
    }

    template <typename IntegerType>
    constexpr auto operator>>(IntegerType shift) noexcept -> byte
    {
        return byte{bits_ >> shift};
    }

    constexpr auto operator|(byte rhs) const noexcept -> byte
    {
        return byte{static_cast<std::uint8_t>(bits_ | rhs.bits_)};
    }

    constexpr auto operator&(byte rhs) const noexcept -> byte
    {
        return byte{static_cast<std::uint8_t>(bits_ & rhs.bits_)};
    }

    constexpr auto operator^(byte rhs) const noexcept -> byte
    {
        return byte{static_cast<std::uint8_t>(bits_ ^ rhs.bits_)};
    }

    constexpr auto operator~() const noexcept -> byte
    {
        return byte{static_cast<std::uint8_t>(~bits_)};
    }

    template <typename IntegerType>
    constexpr auto operator<<=(IntegerType shift) noexcept -> byte&
    {
        bits_ <<= shift;
        return *this;
    }

    template <typename IntegerType>
    constexpr auto operator >>=(IntegerType shift) noexcept -> byte&
    {
        bits_ >>= shift;
        return *this;
    }

    constexpr auto operator|(byte rhs) noexcept -> byte&
    {
        bits_ = static_cast<std::uint8_t>(bits_ | rhs.bits_);
        return *this;
    }

    constexpr auto operator&(byte rhs) noexcept -> byte&
    {
        bits_ = static_cast<std::uint8_t>(bits_ & rhs.bits_);
        return *this;
    }

    constexpr auto operator^(byte rhs) noexcept -> byte&
    {
        bits_ = static_cast<std::uint8_t>(bits_ ^ rhs.bits_);
        return *this;
    }

    constexpr auto operator~() noexcept -> byte&
    {
        bits_ = ~bits_;
        return *this;
    }
};

} // namespace crypt
} // namespace boost

#endif //BOOST_CRYPT_UTILITY_BYTE_HPP
