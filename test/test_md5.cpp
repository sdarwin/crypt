// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// Start with the sample hashes from wiki

#include <boost/crypt/hash/md5.hpp>
#include <boost/core/lightweight_test.hpp>

#ifdef __clang__
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wconversion"
#  pragma clang diagnostic ignored "-Wold-style-cast"
#elif defined(__GNUC__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wconversion"
#  pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

#include <boost/uuid/detail/md5.hpp>

#ifdef __clang__
#  pragma clang diagnostic pop
#elif defined(__GNUC__)
#  pragma GCC diagnostic pop
#endif


#include <random>
#include <iostream>
#include <string>
#include <array>
#include <tuple>
#include <cstdlib>
#include <ctime>
#include <cstring>

void generate_random_cstring(char* str, std::size_t length)
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

auto get_boost_uuid_result(const char* str, size_t length)
{
    unsigned char digest[16];
    boost::uuids::detail::md5 hasher;
    hasher.process_bytes(str, length);
    hasher.get_digest(digest);

    std::array<unsigned char, 16> return_array {};
    for (std::size_t i {}; i < 16U; ++i)
    {
        return_array[i] = digest[i];
    }

    return return_array;
}

constexpr std::array<std::tuple<const char*, std::array<uint16_t, 16>>, 9> test_values =
{
    std::make_tuple("The quick brown fox jumps over the lazy dog",
                    std::array<std::uint16_t, 16>{0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6}),
    std::make_tuple("The quick brown fox jumps over the lazy dog.",
                    std::array<std::uint16_t, 16>{0xe4, 0xd9, 0x09, 0xc2, 0x90, 0xd0, 0xfb, 0x1c, 0xa0, 0x68, 0xff, 0xad, 0xdf, 0x22, 0xcb, 0xd0}),
    std::make_tuple("",
                    std::array<std::uint16_t, 16>{0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e}),
    std::make_tuple("ddcc8542894a27456bbeb43f51f38764c32f72ae",
                    std::array<std::uint16_t, 16>{0x3b, 0x34, 0x0f, 0x00, 0x97, 0x31, 0x2e, 0xc8, 0x2f, 0xa4, 0xda, 0x0d, 0x7d, 0xa5, 0x30, 0x02}),
    std::make_tuple("webmin1980",
                    std::array<std::uint16_t, 16>{0xb7, 0x8a, 0xae, 0x35, 0x67, 0x09, 0xf8, 0xc3, 0x11, 0x18, 0xea, 0x61, 0x39, 0x80, 0x95, 0x4b}),
    std::make_tuple("$2y$10$EQAmcJw0cg.rt.6..SJ2bulFhDo0eWtuMhkfDMPGsNdap4xrOY61K",
                    std::array<std::uint16_t, 16>{0x40, 0xbb, 0xe6, 0x64, 0x4e, 0xfd, 0x93, 0x54, 0x07, 0x8d, 0x8c, 0x70, 0xfb, 0x6c, 0x9f, 0x42}),
    std::make_tuple("pkirsanov",
                    std::array<std::uint16_t, 16>{0x87, 0x93, 0xce, 0x04, 0xf0, 0xc5, 0xf1, 0xe8, 0xed, 0x1e, 0x0c, 0x78, 0xf2, 0x49, 0xfe, 0x1b}),
    std::make_tuple("Eleanor",
                    std::array<std::uint16_t, 16>{0xd3, 0x7e, 0x43, 0x17, 0x49, 0x05, 0xde, 0x70, 0xfb, 0xb5, 0xb0, 0x38, 0xd7, 0x24, 0x7f, 0x57}),
    std::make_tuple("The Whirlpool Galaxy is about 88% the size of the Milky Way, with a diameter of 76,900 light-years",
                    std::array<std::uint16_t, 16>{0xd5, 0xdf, 0xd7, 0xb4, 0x12, 0x35, 0xab, 0xc7, 0xa9, 0xa3, 0x20, 0x5b, 0x68, 0x96, 0xf3, 0x4d}),
};

void basic_tests()
{
    for (const auto& test_value : test_values)
    {
        const auto message_result {boost::crypt::md5(std::get<0>(test_value))};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
    }
}

void string_test()
{
    for (const auto& test_value : test_values)
    {
        const std::string string_message {std::get<0>(test_value)};
        const auto message_result {boost::crypt::md5(string_message)};
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
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
        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }
    }
    #endif
}

void bad_input()
{
    const auto null_message {boost::crypt::md5(static_cast<const char*>(nullptr))};
    BOOST_TEST_EQ(null_message[0], 0x0);
    BOOST_TEST_EQ(null_message[1], 0x0);
    BOOST_TEST_EQ(null_message[2], 0x0);
    BOOST_TEST_EQ(null_message[3], 0x0);

    const auto null_message_len {boost::crypt::md5(static_cast<const char*>(nullptr), 100)};
    BOOST_TEST_EQ(null_message_len[0], 0x0);
    BOOST_TEST_EQ(null_message_len[1], 0x0);
    BOOST_TEST_EQ(null_message_len[2], 0x0);
    BOOST_TEST_EQ(null_message_len[3], 0x0);

    const auto unsigned_null_message {boost::crypt::md5(static_cast<const std::uint8_t*>(nullptr))};
    BOOST_TEST_EQ(unsigned_null_message[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message[3], 0x0);

    const auto unsigned_null_message_len {boost::crypt::md5(static_cast<const std::uint8_t*>(nullptr), 100)};
    BOOST_TEST_EQ(unsigned_null_message_len[0], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[1], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[2], 0x0);
    BOOST_TEST_EQ(unsigned_null_message_len[3], 0x0);
    
    std::string test_str {"Test string"};
    const auto reveresed_input {boost::crypt::detail::md5(test_str.end(), test_str.begin())};
    BOOST_TEST_EQ(reveresed_input[0], 0x0);
    BOOST_TEST_EQ(reveresed_input[1], 0x0);
    BOOST_TEST_EQ(reveresed_input[2], 0x0);
    BOOST_TEST_EQ(reveresed_input[3], 0x0);
}

void test_class()
{
    boost::crypt::md5_hasher hasher;

    for (const auto& test_value : test_values)
    {
        const auto msg {std::get<0>(test_value)};
        hasher.process_bytes(msg, std::strlen(msg));
        const auto message_result {hasher.get_digest()};

        const auto valid_result {std::get<1>(test_value)};
        for (std::size_t i {}; i < message_result.size(); ++i)
        {
            if (!BOOST_TEST_EQ(message_result[i], valid_result[i]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with: " << std::get<0>(test_value) << '\n';
                break;
                // LCOV_EXCL_STOP
            }
        }

        hasher.init();
    }
}

void test_random_values()
{
    constexpr std::size_t max_str_len {65535U};
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<std::size_t> str_len(1, max_str_len - 1);

    char* str {new char[max_str_len]};

    for (std::size_t i {}; i < 1024; ++i)
    {
        std::memset(str, '\0', max_str_len);
        const std::size_t current_str_len {str_len(rng)};
        generate_random_cstring(str, current_str_len);
        const auto uuid_res {get_boost_uuid_result(str, current_str_len)};
        const auto crypt_res {boost::crypt::md5(str, current_str_len)};

        for (std::size_t j {}; j < crypt_res.size(); ++j)
        {
            if (!BOOST_TEST_EQ(uuid_res[j], crypt_res[j]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with string: " << str << std::endl;
                break;
                // LCOV_EXCL_STOP
            }
        }
    }

    delete[] str;
}

void test_random_piecewise_values()
{
    constexpr std::size_t max_str_len {65535U};
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<std::size_t> str_len(1, max_str_len - 1);

    char* str {new char[max_str_len]};
    char* str_2 {new char[max_str_len]};

    for (std::size_t i {}; i < 1024; ++i)
    {
        boost::uuids::detail::md5 boost_hasher;
        boost::crypt::md5_hasher md5_hasher;

        std::memset(str, '\0', max_str_len);
        std::memset(str_2, '\0', max_str_len);

        const std::size_t current_str_len {str_len(rng)};
        generate_random_cstring(str, current_str_len);
        generate_random_cstring(str_2, current_str_len);

        boost_hasher.process_bytes(str, current_str_len);
        boost_hasher.process_bytes(str_2, current_str_len);
        boost_hasher.process_byte(52); // "4"
        unsigned char digest[16];
        boost_hasher.get_digest(digest);

        std::array<unsigned char, 16> uuid_res {};
        for (std::size_t j {}; j < 16U; ++j)
        {
            uuid_res[j] = digest[j];
        }

        md5_hasher.process_bytes(str, current_str_len);
        md5_hasher.process_bytes(str_2, current_str_len);
        md5_hasher.process_byte(52); // "4"
        const auto crypt_res {md5_hasher.get_digest()};

        for (std::size_t j {}; j < crypt_res.size(); ++j)
        {
            if (!BOOST_TEST_EQ(uuid_res[j], crypt_res[j]))
            {
                // LCOV_EXCL_START
                std::cerr << "Failure with string: " << str << std::endl;
                break;
                // LCOV_EXCL_STOP
            }
        }
    }

    delete[] str;
    delete[] str_2;
}

int main()
{
    basic_tests();
    string_test();
    string_test();
    string_view_test();

    bad_input();

    test_class();

    test_random_values();
    test_random_piecewise_values();

    return boost::report_errors();
}