#!/usr/bin/env python3
# Copyright (c) 2018 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the getblockfilter RPC.

- introduce a network split
- work on chains of different lengths
- join the network together again
- verify that getchaintips now returns two chain tips.
"""

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_is_hex_string, assert_raises_rpc_error

class GetBlockFilterTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1

    def run_test (self):
        self.nodes[0].generate(5)

        # Test getblockfilter returns a filter for all blocks and filter types
        for block_height in range(6):
            block_hash = self.nodes[0].getblockhash(block_height)
            for filter_type in range(2):
                result = self.nodes[0].getblockfilter(block_hash, filter_type)
                assert_is_hex_string(result['filter'])

        # Test getblockfilter with unknown block
        bad_block_hash = "0123456789abcdef" * 4
        assert_raises_rpc_error(-5, "Block not found", self.nodes[0].getblockfilter, bad_block_hash, 0)

        # Test getblockfilter with undefined filter type
        genesis_hash = self.nodes[0].getblockhash(0)
        assert_raises_rpc_error(-1, "unknown filter_type", self.nodes[0].getblockfilter, genesis_hash, -1)
        assert_raises_rpc_error(-1, "unknown filter_type", self.nodes[0].getblockfilter, genesis_hash, 2)

if __name__ == '__main__':
    GetBlockFilterTest().main()
