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
    static constexpr boost::crypt::array<boost::crypt::uint32_t, 4> K {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

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

    for (std::size_t i {}; i < 20U; ++i)
    {
        const auto temp {detail::rotl(5U, A) + ((B & C) | ((~B) & D)) + E + W[i] + K[0]};
        E = D;
        D = C;
        C = detail::rotl(30U, B);
        B = A;
        A = temp;
    }

    for (std::size_t i {20U}; i < 40U; ++i)
    {
        const auto temp {detail::rotl(5U, A) + (B ^ C ^ D) + E + W[i] + K[1]};
        E = D;
        D = C;
        C = detail::rotl(30U, B);
        B = A;
        A = temp;
    }

    for (std::size_t i {40U}; i < 60U; ++i)
    {
        const auto temp {detail::rotl(5U, A) + ((B & C) | (B & D) | (C & D)) + E + W[i] + K[2]};
        E = D;
        D = C;
        C = detail::rotl(30U, B);
        B = A;
        A = temp;
    }

    for (std::size_t i {60U}; i < 80U; ++i)
    {
        const auto temp {detail::rotl(5U, A) + (B ^ C ^ D) + E + W[i] + K[3]};
        E = D;
        D = C;
        C = detail::rotl(30U, B);
        B = A;
        A = temp;
    }

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
