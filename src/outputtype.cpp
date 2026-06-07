// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "outputtype.h"
#include "script/standard.h"
#include "pubkey.h"

#include <assert.h>
#include <string>

bool ParseOutputType(const std::string& str, OutputType& output_type)
{
    if (str == "legacy") {
        output_type = OutputType::LEGACY;
        return true;
    }
    if (str == "p2sh-segwit") {
        output_type = OutputType::P2SH_SEGWIT;
        return true;
    }
    if (str == "bech32") {
        output_type = OutputType::BECH32;
        return true;
    }
    if (str == "pq") {
        output_type = OutputType::PQ;
        return true;
    }
    return false;
}

const char* FormatOutputType(OutputType type)
{
    switch (type) {
    case OutputType::LEGACY:      return "legacy";
    case OutputType::P2SH_SEGWIT: return "p2sh-segwit";
    case OutputType::BECH32:      return "bech32";
    case OutputType::PQ:           return "pq";
    }
    assert(false);
    return nullptr; // unreachable, but keeps compiler happy
}

CTxDestination GetDestinationForKey(const CPubKey& key, OutputType type)
{
    switch (type) {
    case OutputType::LEGACY:
        return key.GetID();

    case OutputType::P2SH_SEGWIT: {
        // Оборачиваем P2WPKH в P2SH.
        // ВАЖНО: вызывающий код (CWallet::GetDestinationForKey) обязан
        // вызвать AddCScript(script) чтобы redeemScript был сохранён в wallet.
        WitnessV0KeyHash witnessKeyHash(key.GetID());
        CScript redeemScript = GetScriptForDestination(witnessKeyHash);
        return CScriptID(redeemScript);
    }

    case OutputType::BECH32:
        return WitnessV0KeyHash(key.GetID());

    case OutputType::PQ:
        return CNoDestination();
    }

    assert(false);
    return CNoDestination(); // unreachable
}
