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

// ----- Has CXX something -----
// C++17
#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
#  if __has_include(<string_view>)
#    include <string_view>
#    if defined(__cpp_lib_string_view) && __cpp_lib_string_view >= 201606L
#      define BOOST_CRYPT_HAS_STRING_VIEW
#    endif
#  endif
#endif
// ----- Has CXX something -----

#endif //BOOST_CRYPT_DETAIL_CONFIG_HPP
