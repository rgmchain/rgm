// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef RGM_SCRIPT_STANDARD_H
#define RGM_SCRIPT_STANDARD_H

#include "script/interpreter.h"
#include "uint256.h"

#include <boost/variant.hpp>

#include <stdint.h>

static const bool DEFAULT_ACCEPT_DATACARRIER = true;

class CKeyID;
class CScript;

/** A reference to a CScript: the Hash160 of its serialization (see script.h) */
class CScriptID : public uint160
{
public:
    CScriptID() : uint160() {}
    CScriptID(const CScript& in);
    CScriptID(const uint160& in) : uint160(in) {}
};

static const unsigned int MAX_OP_RETURN_RELAY = 83; //!< bytes (+1 for OP_RETURN, +2 for the pushdata opcodes)
extern bool fAcceptDatacarrier;
extern unsigned nMaxDatacarrierBytes;

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
static const unsigned int MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH;

// Witness program sizes
static const size_t WITNESS_V0_KEYHASH_SIZE    = 20;
static const size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;

enum txnouttype
{
    TX_NONSTANDARD,
    // 'standard' transaction types:
    TX_PUBKEY,
    TX_PUBKEYHASH,
    TX_SCRIPTHASH,
    TX_MULTISIG,
    TX_NULL_DATA,
    TX_WITNESS_V0_SCRIPTHASH,
    TX_WITNESS_V0_KEYHASH,
    TX_WITNESS_UNKNOWN, //!< Only for Solver()
    TX_WITNESS_V0_PQKEYHASH, // ML-DSA-44 post-quantum keyhash (witness v2)
};

class CNoDestination {
public:
    friend bool operator==(const CNoDestination &a, const CNoDestination &b) { return true; }
    friend bool operator<(const CNoDestination &a, const CNoDestination &b) { return true; }
};

/**
 * Native SegWit P2WPKH destination: OP_0 <20-byte-key-hash>
 * Encodes as bech32: rgm1... / trgm1... / rrgm1...
 */
struct WitnessV0KeyHash : public uint160
{
    WitnessV0KeyHash() : uint160() {}
    explicit WitnessV0KeyHash(const uint160& hash) : uint160(hash) {}

    friend bool operator==(const WitnessV0KeyHash& a, const WitnessV0KeyHash& b) {
        return static_cast<const uint160&>(a) == static_cast<const uint160&>(b);
    }
    friend bool operator<(const WitnessV0KeyHash& a, const WitnessV0KeyHash& b) {
        return static_cast<const uint160&>(a) < static_cast<const uint160&>(b);
    }
};

/**
 * Native SegWit P2WSH destination: OP_0 <32-byte-script-hash>
 * Encodes as bech32: rgm1... (longer than P2WPKH)
 */
struct WitnessV0ScriptHash : public uint256
{
    WitnessV0ScriptHash() : uint256() {}
    explicit WitnessV0ScriptHash(const uint256& hash) : uint256(hash) {}

    friend bool operator==(const WitnessV0ScriptHash& a, const WitnessV0ScriptHash& b) {
        return static_cast<const uint256&>(a) == static_cast<const uint256&>(b);
    }
    friend bool operator<(const WitnessV0ScriptHash& a, const WitnessV0ScriptHash& b) {
        return static_cast<const uint256&>(a) < static_cast<const uint256&>(b);
    }
};

/**
 * Unknown witness version destination (version 1..16).
 * Stored for future soft forks (Taproot etc).
 */
struct WitnessUnknown
{
    unsigned int version;
    unsigned int length;
    unsigned char program[40];

    friend bool operator==(const WitnessUnknown& w1, const WitnessUnknown& w2)
    {
        if (w1.version != w2.version) return false;
        if (w1.length  != w2.length)  return false;
        for (unsigned int i = 0; i < w1.length; ++i) {
            if (w1.program[i] != w2.program[i]) return false;
        }
        return true;
    }

    friend bool operator<(const WitnessUnknown& w1, const WitnessUnknown& w2)
    {
        if (w1.version < w2.version) return true;
        if (w1.version > w2.version) return false;
        if (w1.length  < w2.length)  return true;
        if (w1.length  > w2.length)  return false;
        for (unsigned int i = 0; i < w1.length; ++i) {
            if (w1.program[i] < w2.program[i]) return true;
            if (w1.program[i] > w2.program[i]) return false;
        }
        return false;
    }
};

/**
 * A txout script template with a specific destination. It is either:
 *  * CNoDestination         — no destination set
 *  * CKeyID                 — TX_PUBKEYHASH (legacy R... address)
 *  * CScriptID              — TX_SCRIPTHASH (P2SH, includes P2SH-wrapped SegWit)
 *  * WitnessV0KeyHash       — TX_WITNESS_V0_KEYHASH (native bech32 P2WPKH)
 *  * WitnessV0ScriptHash    — TX_WITNESS_V0_SCRIPTHASH (native bech32 P2WSH)
 *  * WitnessUnknown         — future witness versions
 */
typedef boost::variant<
    CNoDestination,
    CKeyID,
    CScriptID,
    WitnessV0KeyHash,
    WitnessV0ScriptHash,
    WitnessUnknown
> CTxDestination;

const char* GetTxnOutputType(txnouttype t);

bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet);
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);
bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet);

CScript GetScriptForDestination(const CTxDestination& dest);
CScript GetScriptForRawPubKey(const CPubKey& pubkey);
CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys);
CScript GetScriptForWitness(const CScript& redeemscript);

/** Check whether a CTxDestination is a valid (non-empty) destination */
bool IsValidDestination(const CTxDestination& dest);

#endif // BITCOIN_SCRIPT_STANDARD_H
