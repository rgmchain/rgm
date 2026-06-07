// Copyright (c) 2021 The RGM Core developers
// Copyright (c) 2026 The RGM Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RGM_FEES_H
#define RGM_FEES_H

#include "amount.h"
#include "chain.h"
#include "chainparams.h"

#ifdef ENABLE_WALLET

enum FeeRatePreset
{
    MINIMUM,
    MORE,
    WOW,
    AMAZE,
    MANY_GENEROUS,
    SUCH_EXPENSIVE
};

/** RGM: Get fee rate for a given priority level */
CFeeRate GetDogecoinFeeRate(int priority);
const std::string GetRGMPriorityLabel(int priority);
#endif // ENABLE_WALLET
CAmount GetRGMMinRelayFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree);
CAmount GetRGMDustFee(const std::vector<CTxOut> &vout, const CAmount dustLimit);

#endif // RGM_FEES_H
