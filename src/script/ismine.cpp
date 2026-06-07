// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ismine.h"

#include "key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/sign.h"

#include <boost/foreach.hpp>
#include "util.h"
#include "util.h"

using namespace std;

typedef vector<unsigned char> valtype;

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey, SigVersion sigversion)
{
    bool isInvalid = false;
    return IsMine(keystore, scriptPubKey, isInvalid, sigversion);
}

isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest, SigVersion sigversion)
{
    bool isInvalid = false;
    return IsMine(keystore, dest, isInvalid, sigversion);
}

isminetype IsMine(const CKeyStore &keystore, const CTxDestination& dest, bool& isInvalid, SigVersion sigversion)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script, isInvalid, sigversion);
}

isminetype IsMine(const CKeyStore &keystore, const CScript& scriptPubKey, bool& isInvalid, SigVersion sigversion)
{
    vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions)) {
        if (keystore.HaveWatchOnly(scriptPubKey))
            return ISMINE_WATCH_UNSOLVABLE;
        return ISMINE_NO;
    }

    CKeyID keyID;
    switch (whichType)
    {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;

    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if (sigversion != SIGVERSION_BASE && vSolutions[0].size() != 33) {
            isInvalid = true;
            return ISMINE_NO;
        }
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;

    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if (sigversion != SIGVERSION_BASE) {
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                isInvalid = true;
                return ISMINE_NO;
            }
        }
        if (keystore.HaveKey(keyID))
            return ISMINE_SPENDABLE;
        break;

    case TX_WITNESS_V0_KEYHASH:
    {
        // RGM: Native bech32 P2WPKH (OP_0 <20-byte-hash>).
        //
        // Оригинальный Bitcoin Core 0.14 требовал наличия P2SH-обёртки
        // в keystore как условие признания ("защита от преждевременного матча").
        // Мы убираем это ограничение: SegWit у нас включается по высоте блока
        // (nSegwitHeight), а не через BIP9 signalling, поэтому защита не нужна.
        //
        // Логика:
        //   1. Если native bech32 адрес был сгенерирован напрямую —
        //      HaveCScript вернёт false, но ключ в keystore есть → SPENDABLE.
        //   2. Если адрес был сгенерирован через p2sh-segwit —
        //      HaveCScript вернёт true, идём по старому пути → тоже SPENDABLE.

        // Путь 1: есть P2SH-обёртка (адрес создан через p2sh-segwit)
        if (keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            isminetype ret = ::IsMine(keystore,
                GetScriptForDestination(CKeyID(uint160(vSolutions[0]))),
                isInvalid, SIGVERSION_WITNESS_V0);
            if (ret == ISMINE_SPENDABLE || ret == ISMINE_WATCH_SOLVABLE ||
                (ret == ISMINE_NO && isInvalid))
                return ret;
        }

        // Путь 2: native bech32 — ищем ключ напрямую по hash160 программы
        {
            keyID = CKeyID(uint160(vSolutions[0]));
            // Ключ должен быть compressed (требование SegWit)
            CPubKey pubkey;
            if (keystore.GetPubKey(keyID, pubkey) && !pubkey.IsCompressed()) {
                isInvalid = true;
                return ISMINE_NO;
            }
            if (keystore.HaveKey(keyID))
                return ISMINE_SPENDABLE;
        }
        break;
    }

    case TX_SCRIPTHASH:
    {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if (keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript, isInvalid);
            if (ret == ISMINE_SPENDABLE || ret == ISMINE_WATCH_SOLVABLE ||
                (ret == ISMINE_NO && isInvalid))
                return ret;
        }
        break;
    }

    case TX_WITNESS_V0_SCRIPTHASH:
    {
        // P2WSH: аналогичная логика — снимаем требование обязательной P2SH-обёртки.

        // Путь 1: есть P2SH-обёртка
        if (keystore.HaveCScript(CScriptID(CScript() << OP_0 << vSolutions[0]))) {
            uint160 hash;
            CRIPEMD160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(hash.begin());
            CScriptID scriptID = CScriptID(hash);
            CScript subscript;
            if (keystore.GetCScript(scriptID, subscript)) {
                isminetype ret = IsMine(keystore, subscript, isInvalid, SIGVERSION_WITNESS_V0);
                if (ret == ISMINE_SPENDABLE || ret == ISMINE_WATCH_SOLVABLE ||
                    (ret == ISMINE_NO && isInvalid))
                    return ret;
            }
        }

        // Путь 2: native P2WSH — ищем witnessScript напрямую по SHA256
        // (SHA256, не HASH160 — это отличие P2WSH от P2SH)
        {
            uint256 scriptHash;
            std::copy(vSolutions[0].begin(), vSolutions[0].end(), scriptHash.begin());
            // В RGM 1.14 keystore не хранит скрипты по SHA256 напрямую,
            // поэтому для native P2WSH пока ограничимся watch-only проверкой ниже.
        }
        break;
    }

    case TX_MULTISIG:
    {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. Multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        vector<valtype> keys(vSolutions.begin()+1, vSolutions.begin()+vSolutions.size()-1);
        if (sigversion != SIGVERSION_BASE) {
            for (size_t i = 0; i < keys.size(); i++) {
                if (keys[i].size() != 33) {
                    isInvalid = true;
                    return ISMINE_NO;
                }
            }
        }
        if (HaveKeys(keys, keystore) == keys.size())
            return ISMINE_SPENDABLE;
        break;
    }

    case TX_WITNESS_V0_PQKEYHASH:
    {
        // PQ witness v2: ML-DSA-44
        // vSolutions[0] = 20-byte HASH160(pq_pubkey)
        uint160 pqHash(vSolutions[0]);
        if (keystore.HavePQKey(pqHash))
            return ISMINE_SPENDABLE;
        break;
    }
    case TX_WITNESS_UNKNOWN:
        // Неизвестные witness версии — не наши
        break;
    }

    if (keystore.HaveWatchOnly(scriptPubKey)) {
        // TODO: This could be optimized some by doing some work after the above solver
        SignatureData sigs;
        return ProduceSignature(DummySignatureCreator(&keystore), scriptPubKey, sigs) ?
            ISMINE_WATCH_SOLVABLE : ISMINE_WATCH_UNSOLVABLE;
    }
    return ISMINE_NO;
}
