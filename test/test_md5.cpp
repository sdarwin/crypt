// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt
//
// Start with the sample hashes from wiki

#include <boost/crypt/hash/md5.hpp>
#include <boost/core/lightweight_test.hpp>

void basic_tests()
{
    const auto message_1_result {boost::crypt::md5("The quick brown fox jumps over the lazy dog")};
    BOOST_TEST_EQ(message_1_result[0], 0x9e107d9d);
    BOOST_TEST_EQ(message_1_result[1], 0x372bb682);
    BOOST_TEST_EQ(message_1_result[2], 0x6bd81d35);
    BOOST_TEST_EQ(message_1_result[3], 0x42a419d6);

    const auto message_2_result {boost::crypt::md5("The quick brown fox jumps over the lazy dog.")};
    BOOST_TEST_EQ(message_2_result[0], 0xe4d909c2);
    BOOST_TEST_EQ(message_2_result[1], 0x90d0fb1c);
    BOOST_TEST_EQ(message_2_result[2], 0xa068ffad);
    BOOST_TEST_EQ(message_2_result[3], 0xdf22cbd0);

    const auto message_3_result {boost::crypt::md5("")};
    BOOST_TEST_EQ(message_3_result[0], 0xd41d8cd9);
    BOOST_TEST_EQ(message_3_result[1], 0x8f00b204);
    BOOST_TEST_EQ(message_3_result[2], 0xe9800998);
    BOOST_TEST_EQ(message_3_result[3], 0xecf8427e);
}

int main()
{
    basic_tests();

    return boost::report_errors();
}
