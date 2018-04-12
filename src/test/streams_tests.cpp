// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <streams.h>
#include <support/allocators/zeroafterfree.h>
#include <test/test_bitcoin.h>

#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/test/unit_test.hpp>

using namespace boost::assign; // bring 'operator+=()' into scope

BOOST_FIXTURE_TEST_SUITE(streams_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(streams_vector_writer)
{
    unsigned char a(1);
    unsigned char b(2);
    unsigned char bytes[] = { 3, 4, 5, 6 };
    std::vector<unsigned char> vch;

    // Each test runs twice. Serializing a second time at the same starting
    // point should yield the same results, even if the first test grew the
    // vector.

    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 0, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{1, 2}}));
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 0, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{1, 2}}));
    vch.clear();

    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 2, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 1, 2}}));
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 2, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 1, 2}}));
    vch.clear();

    vch.resize(5, 0);
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 2, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 1, 2, 0}}));
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 2, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 1, 2, 0}}));
    vch.clear();

    vch.resize(4, 0);
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 3, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 0, 1, 2}}));
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 3, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 0, 1, 2}}));
    vch.clear();

    vch.resize(4, 0);
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 4, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 0, 0, 1, 2}}));
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 4, a, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{0, 0, 0, 0, 1, 2}}));
    vch.clear();

    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 0, bytes);
    BOOST_CHECK((vch == std::vector<unsigned char>{{3, 4, 5, 6}}));
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 0, bytes);
    BOOST_CHECK((vch == std::vector<unsigned char>{{3, 4, 5, 6}}));
    vch.clear();

    vch.resize(4, 8);
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 2, a, bytes, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{8, 8, 1, 3, 4, 5, 6, 2}}));
    CVectorWriter(SER_NETWORK, INIT_PROTO_VERSION, vch, 2, a, bytes, b);
    BOOST_CHECK((vch == std::vector<unsigned char>{{8, 8, 1, 3, 4, 5, 6, 2}}));
    vch.clear();
}

BOOST_AUTO_TEST_CASE(streams_vector_reader)
{
    std::vector<unsigned char> vch = {1, 255, 3, 4, 5, 6};

    VectorReader reader(SER_NETWORK, INIT_PROTO_VERSION, vch, 0);
    BOOST_CHECK_EQUAL(reader.size(), 6);
    BOOST_CHECK(!reader.empty());

    // Read a single byte as an unsigned char.
    unsigned char a;
    reader >> a;
    BOOST_CHECK_EQUAL(a, 1);
    BOOST_CHECK_EQUAL(reader.size(), 5);
    BOOST_CHECK(!reader.empty());

    // Read a single byte as a signed char.
    char b;
    reader >> b;
    BOOST_CHECK_EQUAL(b, -1);
    BOOST_CHECK_EQUAL(reader.size(), 4);
    BOOST_CHECK(!reader.empty());

    // Read a 4 bytes as a signed int.
    unsigned int c;
    reader >> c;
    BOOST_CHECK_EQUAL(c, 100992003); // 3,4,5,6 in little-endian base-256
    BOOST_CHECK_EQUAL(reader.size(), 0);
    BOOST_CHECK(reader.empty());

    // Reading after end of byte vector throws an error.
    signed int d;
    BOOST_CHECK_THROW(reader >> d, std::ios_base::failure);

    // Read a 4 bytes as an unsigned int from the beginning of the buffer.
    reader.seek(-6);
    reader >> d;
    BOOST_CHECK_EQUAL(d, 67370753); // 1,255,3,4 in little-endian base-256
    BOOST_CHECK_EQUAL(reader.size(), 2);
    BOOST_CHECK(!reader.empty());

    // Reading after end of byte vector throws an error even if the reader is
    // not totally empty.
    BOOST_CHECK_THROW(reader >> d, std::ios_base::failure);
}

BOOST_AUTO_TEST_CASE(streams_serializedata_xor)
{
    std::vector<char> in;
    std::vector<char> expected_xor;
    std::vector<unsigned char> key;
    CDataStream ds(in, 0, 0);

    // Degenerate case
    
    key += '\x00','\x00';
    ds.Xor(key);
    BOOST_CHECK_EQUAL(
            std::string(expected_xor.begin(), expected_xor.end()), 
            std::string(ds.begin(), ds.end()));

    in += '\x0f','\xf0';
    expected_xor += '\xf0','\x0f';
    
    // Single character key

    ds.clear();
    ds.insert(ds.begin(), in.begin(), in.end());
    key.clear();

    key += '\xff';
    ds.Xor(key);
    BOOST_CHECK_EQUAL(
            std::string(expected_xor.begin(), expected_xor.end()), 
            std::string(ds.begin(), ds.end())); 
    
    // Multi character key

    in.clear();
    expected_xor.clear();
    in += '\xf0','\x0f';
    expected_xor += '\x0f','\x00';
                        
    ds.clear();
    ds.insert(ds.begin(), in.begin(), in.end());

    key.clear();
    key += '\xff','\x0f';

    ds.Xor(key);
    BOOST_CHECK_EQUAL(
            std::string(expected_xor.begin(), expected_xor.end()), 
            std::string(ds.begin(), ds.end()));  
}         

BOOST_AUTO_TEST_SUITE_END()
