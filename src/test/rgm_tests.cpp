// Copyright (c) 2015-2022 The RGM Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "arith_uint256.h"
#include "chainparams.h"
#include "rgm.h"
#include "test/test_bitcoin.h"
#include "pow.h"
#include "primitives/block.h"
#include "pq/pq_key.h"
#include "pq/pq_pubkey.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(rgm_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(rgm_golden_and_supply)
{
    const CChainParams& mainParams = Params(CBaseChainParams::MAIN);
    const Consensus::Params& p = mainParams.GetConsensus(0);
    const uint256 dummyPrev = uint256();
    const int interval = p.nSubsidyHalvingInterval;

    // RGM halving interval (~4 years at 60s blocks)
    BOOST_CHECK_EQUAL(interval, 2102400);

    // Point checks: base reward, golden x5, genesis guard, halving, tail
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(0, p, dummyPrev), 50 * COIN);        // genesis: h%1000==0 but h>0 guard -> no bonus
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(1, p, dummyPrev), 50 * COIN);        // ordinary
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(999, p, dummyPrev), 50 * COIN);      // ordinary
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(1000, p, dummyPrev), 250 * COIN);    // first golden block: 5x
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(interval - 1, p, dummyPrev), 50 * COIN);   // last block of epoch 0
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(interval, p, dummyPrev), 25 * COIN);       // first halving
    int goldenAfterHalving = ((interval + 999) / 1000) * 1000;               // first golden height after the halving
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(goldenAfterHalving, p, dummyPrev), 125 * COIN); // 25 x5
    BOOST_CHECK_EQUAL(GetRGMBlockSubsidy(64 * interval, p, dummyPrev), 0);    // after 64 halvings: 0

    // Total supply: base halves every interval and the integer >> zeroes it by
    // halving 33, so all emission lives in halvings 0..32. Sum every block and check
    // the total lands ABOVE the 210.24M a no-golden schedule (50 * interval * 2)
    // would give -- that gap is the golden-block bonus.
    CAmount total = 0;
    const long long lastEmittingHeight = 33LL * interval;
    for (long long h = 0; h < lastEmittingHeight; h++)
        total += GetRGMBlockSubsidy((int)h, p, dummyPrev);

    BOOST_TEST_MESSAGE("RGM total supply (satoshis): " << total);
    BOOST_CHECK_EQUAL(total, 21108085783232708LL);   // exact emission from real GetRGMBlockSubsidy
    BOOST_CHECK(total > 210240000LL * COIN);   // golden bonus pushes real supply above the no-golden 210.24M
    BOOST_CHECK(total < 212000000LL * COIN);   // sanity upper bound
}

BOOST_AUTO_TEST_CASE(rgm_emergency_difficulty_reset)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(400);
    const unsigned int powLimit = UintToArith256(params.powLimit).GetCompact();

    // Emergency anti-freeze rule (hardfork live since block 364): activates at
    // height 364 after a 3h stall. REQUIRE so we stop before the diff path if unset.
    BOOST_REQUIRE_EQUAL(params.nEmergencyMinDiffHeight, 364);
    BOOST_REQUIRE_EQUAL(params.nEmergencyMinDiffTimeout, 3 * 60 * 60);

    CBlockIndex pindexLast;
    pindexLast.nHeight = 400;                 // next block 401 >= 364 -> rule active
    pindexLast.nTime   = 1700000000;

    // Block dated more than the 3h timeout after its parent -> min-diff reset.
    CBlockHeader trigger;
    trigger.nTime = pindexLast.nTime + params.nEmergencyMinDiffTimeout + 1;
    BOOST_CHECK_EQUAL(GetNextWorkRequired(&pindexLast, &trigger, params), powLimit);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395094427;

    // First hard-fork at 145,000, which applies to block 145,001 onwards
    pindexLast.nHeight = 145000;
    pindexLast.nTime = 1395094679;
    pindexLast.nBits = 0x1b499dfd;
    BOOST_CHECK_EQUAL(CalculateRGMNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b671062);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_modulated_upper)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395100835;

    // Test the upper bound on modulated time using mainnet block #145,107
    pindexLast.nHeight = 145107;
    pindexLast.nTime = 1395101360;
    pindexLast.nBits = 0x1b3439cd;
    BOOST_CHECK_EQUAL(CalculateRGMNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b4e56b3);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_modulated_lower)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395380517;

    // Test the lower bound on modulated time using mainnet block #149,423
    pindexLast.nHeight = 149423;
    pindexLast.nTime = 1395380447;
    pindexLast.nBits = 0x1b446f21;
    BOOST_CHECK_EQUAL(CalculateRGMNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b335358);
}

BOOST_AUTO_TEST_CASE(get_next_work_digishield_rounding)
{
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& params = Params().GetConsensus(145000);
    
    CBlockIndex pindexLast;
    int64_t nLastRetargetTime = 1395094679;

    // Test case for correct rounding of modulated time - this depends on
    // handling of integer division, and is not obvious from the code
    pindexLast.nHeight = 145001;
    pindexLast.nTime = 1395094727;
    pindexLast.nBits = 0x1b671062;
    BOOST_CHECK_EQUAL(CalculateRGMNextWorkRequired(&pindexLast, nLastRetargetTime, params), 0x1b6558a4);
}

BOOST_AUTO_TEST_CASE(rgm_pq_sign_verify_roundtrip)
{
    CPQKey key;
    CPQPubKey pub;
    BOOST_REQUIRE(key.MakeNewKey(pub));
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(pub.IsValid());

    std::vector<uint8_t> hash(32, 0x42);
    std::vector<uint8_t> sig = key.Sign(hash);
    BOOST_REQUIRE(!sig.empty());
    BOOST_CHECK(pub.Verify(hash, sig));

    // Tampered hash -> reject
    std::vector<uint8_t> badHash(32, 0x43);
    BOOST_CHECK(!pub.Verify(badHash, sig));

    // Tampered signature -> reject
    std::vector<uint8_t> badSig = sig;
    badSig[0] ^= 0xFF;
    BOOST_CHECK(!pub.Verify(hash, badSig));

    // Clear() wipes the key (secure_allocator + memory_cleanse) and invalidates it
    key.Clear();
    BOOST_CHECK(!key.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
