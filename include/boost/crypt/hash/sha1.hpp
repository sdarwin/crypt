// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// See: https://datatracker.ietf.org/doc/html/rfc3174

#ifndef BOOST_CRYPT_HASH_SHA1_HPP
#define BOOST_CRYPT_HASH_SHA1_HPP

#include <boost/crypt/utility/config.hpp>
#include <boost/crypt/utility/bit.hpp>
#include <boost/crypt/utility/byte.hpp>
#include <boost/crypt/utility/array.hpp>
#include <boost/crypt/utility/cstdint.hpp>
#include <boost/crypt/utility/type_traits.hpp>
#include <boost/crypt/utility/strlen.hpp>
#include <boost/crypt/utility/cstddef.hpp>
#include <boost/crypt/utility/iterator.hpp>
#include <boost/crypt/utility/file.hpp>

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <memory>
#include <string>
#include <cstdint>
#include <cstring>
#endif

namespace boost {
namespace crypt {

class sha1_hasher
{
private:
    boost::crypt::array<boost::crypt::uint32_t, 5> intermediate_hash_ { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    boost::crypt::array<boost::crypt::uint8_t, 64> message_block_ {};

    boost::crypt::size_t message_block_index_ {};

    boost::crypt::size_t low_ {};
    boost::crypt::size_t high_ {};

    bool computed {};
    bool corrupted {};

    constexpr auto sha1_process_message_block() -> void;

public:

    BOOST_CRYPT_GPU_ENABLED constexpr auto init() -> void
    {
        intermediate_hash_[0] = 0x67452301;
        intermediate_hash_[1] = 0xEFCDAB89;
        intermediate_hash_[2] = 0x98BADCFE;
        intermediate_hash_[3] = 0x10325476;
        intermediate_hash_[4] = 0xC3D2E1F0;

        message_block_.fill(0);
        message_block_index_ = 0UL;
        low_ = 0UL;
        high_ = 0UL;
        computed = false;
        corrupted = false;
    }
};

namespace detail {

constexpr auto round1(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + ((B & C) | ((~B) & D)) + E + W + 0x5A827999U};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

constexpr auto round2(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + (B ^ C ^ D) + E + W + 0x6ED9EBA1U};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

constexpr auto round3(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + ((B & C) | (B & D) | (C & D)) + E + W + 0x8F1BBCDCU};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

constexpr auto round4(boost::crypt::uint32_t& A,
                      boost::crypt::uint32_t& B,
                      boost::crypt::uint32_t& C,
                      boost::crypt::uint32_t& D,
                      boost::crypt::uint32_t& E,
                      boost::crypt::uint32_t  W)
{
    const auto temp {detail::rotl(5U, A) + (B ^ C ^ D) + E + W + 0xCA62C1D6U};
    E = D;
    D = C;
    C = detail::rotl(30U, B);
    B = A;
    A = temp;
}

} // Namespace detail

constexpr auto sha1_hasher::sha1_process_message_block() -> void
{
    boost::crypt::array<boost::crypt::uint32_t, 80> W {};

    // Init the first 16 words of W
    for (boost::crypt::size_t i {}; i < 16UL; ++i)
    {
        W[i] = (static_cast<boost::crypt::uint32_t>(message_block_[i * 4U]) << 24U) |
               (static_cast<boost::crypt::uint32_t>(message_block_[i * 4U + 1U]) << 16U) |
               (static_cast<boost::crypt::uint32_t>(message_block_[i * 4U + 2U]) << 8U) |
               (static_cast<boost::crypt::uint32_t>(message_block_[i * 4U + 3U]));

    }

    for (boost::crypt::size_t i {16U}; i < W.size(); ++i)
    {
        W[i] = detail::rotl(1U, W[i - 3U] ^ W[i - 8U] ^ W[i - 14] ^ W[i - 16]);
    }

    auto A {intermediate_hash_[0]};
    auto B {intermediate_hash_[1]};
    auto C {intermediate_hash_[2]};
    auto D {intermediate_hash_[3]};
    auto E {intermediate_hash_[4]};

    // Round 1
    detail::round1(A, B, C, D, E, W[0]);
    detail::round1(A, B, C, D, E, W[1]);
    detail::round1(A, B, C, D, E, W[2]);
    detail::round1(A, B, C, D, E, W[3]);
    detail::round1(A, B, C, D, E, W[4]);
    detail::round1(A, B, C, D, E, W[5]);
    detail::round1(A, B, C, D, E, W[6]);
    detail::round1(A, B, C, D, E, W[7]);
    detail::round1(A, B, C, D, E, W[8]);
    detail::round1(A, B, C, D, E, W[9]);
    detail::round1(A, B, C, D, E, W[10]);
    detail::round1(A, B, C, D, E, W[11]);
    detail::round1(A, B, C, D, E, W[12]);
    detail::round1(A, B, C, D, E, W[13]);
    detail::round1(A, B, C, D, E, W[14]);
    detail::round1(A, B, C, D, E, W[15]);
    detail::round1(A, B, C, D, E, W[16]);
    detail::round1(A, B, C, D, E, W[18]);
    detail::round1(A, B, C, D, E, W[19]);

    // Round 2
    detail::round2(A, B, C, D, E, W[20]);
    detail::round2(A, B, C, D, E, W[21]);
    detail::round2(A, B, C, D, E, W[22]);
    detail::round2(A, B, C, D, E, W[23]);
    detail::round2(A, B, C, D, E, W[24]);
    detail::round2(A, B, C, D, E, W[25]);
    detail::round2(A, B, C, D, E, W[26]);
    detail::round2(A, B, C, D, E, W[27]);
    detail::round2(A, B, C, D, E, W[28]);
    detail::round2(A, B, C, D, E, W[29]);
    detail::round2(A, B, C, D, E, W[20]);
    detail::round2(A, B, C, D, E, W[31]);
    detail::round2(A, B, C, D, E, W[32]);
    detail::round2(A, B, C, D, E, W[33]);
    detail::round2(A, B, C, D, E, W[34]);
    detail::round2(A, B, C, D, E, W[35]);
    detail::round2(A, B, C, D, E, W[36]);
    detail::round2(A, B, C, D, E, W[38]);
    detail::round2(A, B, C, D, E, W[39]);

    // Round 3
    detail::round3(A, B, C, D, E, W[40]);
    detail::round3(A, B, C, D, E, W[41]);
    detail::round3(A, B, C, D, E, W[42]);
    detail::round3(A, B, C, D, E, W[43]);
    detail::round3(A, B, C, D, E, W[44]);
    detail::round3(A, B, C, D, E, W[45]);
    detail::round3(A, B, C, D, E, W[46]);
    detail::round3(A, B, C, D, E, W[47]);
    detail::round3(A, B, C, D, E, W[48]);
    detail::round3(A, B, C, D, E, W[49]);
    detail::round3(A, B, C, D, E, W[50]);
    detail::round3(A, B, C, D, E, W[51]);
    detail::round3(A, B, C, D, E, W[52]);
    detail::round3(A, B, C, D, E, W[53]);
    detail::round3(A, B, C, D, E, W[54]);
    detail::round3(A, B, C, D, E, W[55]);
    detail::round3(A, B, C, D, E, W[56]);
    detail::round3(A, B, C, D, E, W[58]);
    detail::round3(A, B, C, D, E, W[59]);

    // Round 4
    detail::round4(A, B, C, D, E, W[60]);
    detail::round4(A, B, C, D, E, W[61]);
    detail::round4(A, B, C, D, E, W[62]);
    detail::round4(A, B, C, D, E, W[63]);
    detail::round4(A, B, C, D, E, W[64]);
    detail::round4(A, B, C, D, E, W[65]);
    detail::round4(A, B, C, D, E, W[66]);
    detail::round4(A, B, C, D, E, W[67]);
    detail::round4(A, B, C, D, E, W[68]);
    detail::round4(A, B, C, D, E, W[69]);
    detail::round4(A, B, C, D, E, W[70]);
    detail::round4(A, B, C, D, E, W[71]);
    detail::round4(A, B, C, D, E, W[72]);
    detail::round4(A, B, C, D, E, W[73]);
    detail::round4(A, B, C, D, E, W[74]);
    detail::round4(A, B, C, D, E, W[75]);
    detail::round4(A, B, C, D, E, W[76]);
    detail::round4(A, B, C, D, E, W[78]);
    detail::round4(A, B, C, D, E, W[79]);

    intermediate_hash_[0] += A;
    intermediate_hash_[1] += B;
    intermediate_hash_[2] += C;
    intermediate_hash_[3] += D;
    intermediate_hash_[4] += E;

    message_block_index_ = 0U;
}

} // namespace crypt
} // namepsace boost

#endif // BOOST_CRYPT_HASH_SHA1_HPP
