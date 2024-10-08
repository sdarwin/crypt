// Copyright 2024 Matt Borland
// Distributed under the Boost Software License, Version 1.0.
// https://www.boost.org/LICENSE_1_0.txt

#ifndef BOOST_CRYPT_DETAIL_CONFIG_HPP
#define BOOST_CRYPT_DETAIL_CONFIG_HPP

#ifdef __CUDACC__
#  ifndef BOOST_CRYPT_ENABLE_CUDA
#    define BOOST_CRYPT_ENABLE_CUDA
#  endif
#endif

// ---- Constexpr arrays -----
#if defined(__cpp_inline_variables) && __cpp_inline_variables >= 201606L
#  define BOOST_CRYPT_CONSTEXPR_ARRAY inline constexpr
#  define BOOST_CRYPT_DEVICE_ARRAY inline constexpr
#elif defined(BOOST_CRYPT_ENABLE_CUDA)
#  define BOOST_CYPRT_CONSTEXPR_ARRAY static constexpr
#  define BOOST_CRYPT_DEVICE_ARRAY __constant__
#else
#  define BOOST_CRYPT_CONSTEXPR_ARRAY static constexpr
#  define BOOST_CRYPT_DEVICE_ARRAY static constexpr
#endif
// ---- Constexpr arrays -----

// ----- Assertions -----
#include <cassert>
#define BOOST_CRYPT_ASSERT(x) assert(x)
#define BOOST_CRYPT_ASSERT_MSG(expr, msg) assert((expr)&&(msg))
// ----- Assertions -----

#endif //BOOST_CRYPT_DETAIL_CONFIG_HPP
