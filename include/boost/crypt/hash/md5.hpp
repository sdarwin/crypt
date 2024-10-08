// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_HASH_MD5_HPP
#define BOOST_CRYPT_HASH_MD5_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/bit.hpp>

#include <array>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

namespace boost {
namespace crypt {

namespace detail {

static constexpr std::array<std::uint32_t, 64> S {
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static constexpr std::array<std::uint32_t, 64> K {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

template <typename T>
auto md5_preprocess(T begin, T end) -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> vec;
    vec.reserve(static_cast<std::size_t>(end - begin));
    std::copy(begin, end, std::back_inserter(vec));
    return vec;
}

template <typename T>
auto md5_preprocess(T begin, std::size_t len) -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> vec;
    vec.reserve(len);
    std::copy(begin, begin + len, std::back_inserter(vec));
    return vec;
}

auto md5_pad(const std::vector<std::uint8_t>& message) noexcept -> std::vector<std::uint8_t>
{
    std::vector<std::uint8_t> padded_message {message};
    const std::uint64_t original_length {message.size() * 8U};
    padded_message.emplace_back(0x80);

    while ((padded_message.size() * 8U) % 512U != 448U)
    {
        padded_message.push_back(static_cast<std::uint8_t>(0x00));
    }

    // Add the original length as a 64-bit number
    for (std::size_t i = 0; i < 8; ++i)
    {
        padded_message.push_back(static_cast<std::uint8_t>((original_length >> (8 * i)) & 0xFF));
    }

    return padded_message;
}

template <typename ResultType>
auto md5_impl(const std::vector<std::uint8_t>& padded_message) -> ResultType
{
    std::uint32_t a0 {0x67452301};
    std::uint32_t b0 {0xefcdab89};
    std::uint32_t c0 {0x98badcfe};
    std::uint32_t d0 {0x10325476};

    std::array<std::uint32_t, 16> blocks {};

    std::size_t message_chunk {};
    while (message_chunk < padded_message.size())
    {
        for (auto& block : blocks)
        {
            block = static_cast<std::uint32_t>(
                    (static_cast<std::uint32_t>(padded_message[message_chunk])) +
                    (static_cast<std::uint32_t>(padded_message[message_chunk + 1U]) << 8U) +
                    (static_cast<std::uint32_t>(padded_message[message_chunk + 2U]) << 16U) +
                    (static_cast<std::uint32_t>(padded_message[message_chunk + 3U]) << 24U)
            );

            message_chunk += 4U;
        }

        std::uint32_t A {a0};
        std::uint32_t B {b0};
        std::uint32_t C {c0};
        std::uint32_t D {d0};

        for (std::uint32_t i {}; i < 64U; ++i)
        {
            std::uint32_t F {};
            std::uint32_t g {};

            if (i <= 15U)
            {
                F = (B & C) | ((~B) & D);
                g = i;
            }
            else if (i <= 31U)
            {
                F = (D & B) | ((~D) & C);
                g = (5U * i + 1U) % 16U;
            }
            else if (i <= 47U)
            {
                F = B ^ C ^ D;
                g = (3U * i + 5U) % 16U;
            }
            else
            {
                F = C ^ (B | (~D));
                g = (7U * i) % 16U;
            }

            BOOST_CRYPT_ASSERT(i <= 63U);

            F = F + A + K[i] + blocks[g];
            A = D;
            D = C;
            C = B;
            B = B + rotl(F, S[i]);
        }

        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }

    return ResultType {swap_endian(a0),
                       swap_endian(b0),
                       swap_endian(c0),
                       swap_endian(d0)};
}

} // namespace detail

template <typename ResultType = std::array<std::uint32_t, 4>, typename T>
ResultType md5(T begin, T end)
{
    if (end <= begin)
    {
        return ResultType {0, 0, 0, 0};
    }

    const auto message {detail::md5_preprocess(begin, end)};
    const auto padded_message {detail::md5_pad(message)};
    return detail::md5_impl<ResultType>(padded_message);
}

template <typename ResultType = std::array<std::uint32_t, 4>>
ResultType md5(const char* str)
{
    if (str == nullptr)
    {
        return ResultType {0, 0, 0, 0};
    }

    const auto message_len {std::strlen(str)};
    const auto message {detail::md5_preprocess(str, message_len)};
    const auto padded_message {detail::md5_pad(message)};
    return detail::md5_impl<ResultType>(padded_message);
}

template <typename ResultType = std::array<std::uint32_t, 4>>
ResultType md5(const std::string& str)
{
    return md5(str.begin(), str.end());
}

#ifdef BOOST_CRYPT_HAS_STRING_VIEW
template <typename ResultType = std::array<std::uint32_t, 4>>
ResultType md5(const std::string_view& str)
{
    return md5(str.begin(), str.end());
}
#endif

} // namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_HASH_MD5_HPP
