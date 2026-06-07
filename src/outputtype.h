// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RGM_OUTPUTTYPE_H
#define RGM_OUTPUTTYPE_H

#include "pubkey.h"
#include "script/standard.h"

#include <string>

enum class OutputType {
    LEGACY,
    P2SH_SEGWIT,
    BECH32,
    PQ,
};

//! Default address type: legacy (R... addresses) — не ломает старые кошельки
static const OutputType DEFAULT_ADDRESS_TYPE = OutputType::LEGACY;

//! Default change type: same as address type
static const OutputType DEFAULT_CHANGE_TYPE = OutputType::LEGACY;

//! Parse a string into OutputType. Returns false if string is unknown.
bool ParseOutputType(const std::string& str, OutputType& output_type);

//! Format an OutputType to human-readable string.
const char* FormatOutputType(OutputType type);

/**
 * Get a destination of the requested type (via pubkey) for wallet use.
 *
 * NOTE: For P2SH_SEGWIT this function does NOT call AddCScript — the caller
 * (CWallet::GetDestinationForKey) must do that so the redeemScript is stored.
 * Use the wallet-level wrapper, not this directly, when you need P2SH_SEGWIT.
 */
CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type);

#endif // BITCOIN_OUTPUTTYPE_H
