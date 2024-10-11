// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// Start with the sample hashes from wiki

#include <boost/crypt/hash/md5.hpp>
#include <boost/core/lightweight_test.hpp>
#include <string>
#include <array>
#include <tuple>

constexpr std::array<std::tuple<const char*, uint32_t, uint32_t, uint32_t, uint32_t>, 3> test_values =
{
    std::make_tuple("The quick brown fox jumps over the lazy dog", 0x9e107d9d, 0x372bb682, 0x6bd81d35, 0x42a419d6),
    std::make_tuple("The quick brown fox jumps over the lazy dog.", 0xe4d909c2, 0x90d0fb1c, 0xa068ffad, 0xdf22cbd0),
    std::make_tuple("", 0xd41d8cd9, 0x8f00b204, 0xe9800998, 0xecf8427e)
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::md5(std::get<0>(test_value))};
        BOOST_TEST_EQ(message_result[0], std::get<1>(test_value));
        BOOST_TEST_EQ(message_result[1], std::get<2>(test_value));
        BOOST_TEST_EQ(message_result[2], std::get<3>(test_value));
        BOOST_TEST_EQ(message_result[3], std::get<4>(test_value));
    }
}

void string_test()
{
    for (const auto& test_value : test_values)
    {
        const std::string string_message {std::get<0>(test_value)};
        const auto message_result {boost::crypt::md5(string_message)};
        BOOST_TEST_EQ(message_result[0], std::get<1>(test_value));
        BOOST_TEST_EQ(message_result[1], std::get<2>(test_value));
        BOOST_TEST_EQ(message_result[2], std::get<3>(test_value));
        BOOST_TEST_EQ(message_result[3], std::get<4>(test_value));
    }
}

void string_view_test()
{
    #ifdef BOOST_CRYPT_HAS_STRING_VIEW
    for (const auto& test_value : test_values)
    {
        const std::string string_message {std::get<0>(test_value)};
        const std::string_view string_view_message {string_message};
        const auto message_result {boost::crypt::md5(string_view_message)};
        BOOST_TEST_EQ(message_result[0], std::get<1>(test_value));
        BOOST_TEST_EQ(message_result[1], std::get<2>(test_value));
        BOOST_TEST_EQ(message_result[2], std::get<3>(test_value));
        BOOST_TEST_EQ(message_result[3], std::get<4>(test_value));
    }
    #endif
}

void bad_input()
{
    const auto null_message {boost::crypt::md5(nullptr)};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);
}

void test_class()
{
    boost::crypt::detail::md5 hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg, std::strlen(msg));
        std::array<std::uint32_t, 4> message_result {};
        hasher.get_digest(message_result.begin(), message_result.size());

        BOOST_TEST_EQ(message_result[0], std::get<1>(test_value));
        BOOST_TEST_EQ(message_result[1], std::get<2>(test_value));
        BOOST_TEST_EQ(message_result[2], std::get<3>(test_value));
        BOOST_TEST_EQ(message_result[3], std::get<4>(test_value));

        hasher.init();
    }
}

int main()
{
    basic_tests();
    string_test();
    string_test();
    string_view_test();

    bad_input();

    test_class();

    return boost::report_errors();
}
