// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_TEST_GENERATE_RANDOM_STRINGS
#define BOOST_CRYPT_TEST_GENERATE_RANDOM_STRINGS

#include <random>
#include <cstdlib>
#include <ctime>
#include <cstring>

namespace boost {
namespace crypt {

inline void generate_random_cstring(char* str, std::size_t length)
{

    const char charset[] = "0123456789"
                           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                           "abcdefghijklmnopqrstuvwxyz";

    const std::size_t charset_size = sizeof(charset) - 1;

    std::mt19937_64 rng(42);
    std::uniform_int_distribution<int> dist(0, charset_size);

    for (std::size_t i = 0; i < length - 1; ++i)
    {
        int index = dist(rng);
        str[i] = charset[index];
    }

    str[length - 1] = '\0';
}

} // Namespace crypt
} // namespace boost

#endif // BOOST_CRYPT_TEST_GENERATE_RANDOM_STRINGS
