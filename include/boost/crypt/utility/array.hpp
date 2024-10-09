// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt


#ifndef BOOST_CRYPT_UTILITIES_ARRAY_HPP
#define BOOST_CRYPT_UTILITIES_ARRAY_HPP

#include <boost/crypt/utility/config.hpp>

#ifdef BOOST_CRYPT_ENABLE_CUDA

#include <cuda/std/array>

namespace boost {
namespace crypt {

using cuda::std::array;

} // namespace crypt
} // namespace boost

#else // Use the STL

#ifndef BOOST_CRYPT_BUILD_MODULE
#include <array>
#endif

namespace boost {
namespace crypt {

using std::array;

} // namespace crypt
} // namespace boost

#endif // CUDA

#endif // BOOST_CRYPT_UTILITIES_ARRAY_HPP
