// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2022-2024 The RGM Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>
#include <limits>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                                 int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);

    txNew.vin[0].scriptSig = CScript()
        << 486604799
        << CScriptNum(4)
        << std::vector<unsigned char>(
            (const unsigned char*)pszTimestamp,
            (const unsigned char*)pszTimestamp + strlen(pszTimestamp));

    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits,
                                 int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Date 26/02/2026 Revolutionary Gold Money V1.0";
    const CScript genesisOutputScript = CScript()
        << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9")
        << OP_CHECKSIG;

    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CMainParams() {
        strNetworkID = "main";

        consensus.nSubsidyHalvingInterval = 2102400; // ~4 года при 1 мин/блок
        consensus.nMajorityEnforceBlockUpgrade = 1500;
        consensus.nMajorityRejectBlockOutdated = 1900;
        consensus.nMajorityWindow = 2000;

        // сразу современные правила
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.nQuantumSafeHeight = 50000; // PQ активен с SegWit (блок 50000)

        consensus.powLimit = uint256S("0x00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // Digishield сразу
        // --- RGM: Время блока ---
        consensus.nPowTargetTimespan = 60;       // цель: 60 сек/блок
        consensus.nPowTargetSpacing = 60;        // 60 сек

        // --- RGM: LWMA - быстрая реакция на скачки хешрейта (асики!) ---
        consensus.nLwmaAveragingWindow = 45;     // усреднять 45 блоков (быстрее чем 60)
        consensus.nLwmaHeight = 1;               // LWMA с первого блока

        // --- RGM: DigiShield включён - защита от мультипулов и асиков ---
        consensus.fDigishieldDifficultyCalculation = true;

        // --- RGM: 3 этапа запуска (всё зашито заранее, без хард форков) ---
        // Этап 1: Legacy майнинг (блоки 0 - 10,000) ~9 дней
        consensus.nPoolMiningPhaseHeight = 10000;

        // Этап 2: SegWit (блок 50,000 = ~35 дней от старта)
        // SegWit должен быть активен ДО AuxPoW — чтобы AuxPoW coinbase мог использовать bech32
        consensus.nSegwitHeight = 50000;

        // Этап 3: AuxPoW merge-mining (блок 200,000 = ~139 дней от старта)
        consensus.nAuxpowHeight = 200000;

        consensus.nCoinbaseMaturity = 30;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowAllowRGMMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        consensus.nRuleChangeActivationThreshold = 9576;
        consensus.nMinerConfirmationWindow = 10080;

        // TESTDUMMY выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout   = std::numeric_limits<int64_t>::max();

        // CSV выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout   = std::numeric_limits<int64_t>::max();

        // SegWit выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout   = std::numeric_limits<int64_t>::max();

        consensus.nMinimumChainWork = uint256();
        consensus.defaultAssumeValid = uint256();

        // AuxPoW параметры
        consensus.nAuxpowChainId = 0x5247;

        // ----------------------------------------------------------------
        // RGM: Правильное дерево consensus для переключения этапов
        // ----------------------------------------------------------------

        // Этап 1 (блоки 0 → nAuxpowHeight-1): Legacy блоки разрешены
        consensus.fAllowLegacyBlocks = true;
        consensus.fStrictChainId = false;       // не проверяем chainId до AuxPoW
        consensus.nHeightEffective = 0;         // действует с блока 0

        // Этап 2 (блоки nAuxpowHeight → ...): AuxPoW включён
        auxpowConsensus = consensus;
        auxpowConsensus.fAllowLegacyBlocks = false;  // legacy блоки запрещены!
        auxpowConsensus.fStrictChainId = true;        // строгая проверка chainId
        auxpowConsensus.nHeightEffective = consensus.nAuxpowHeight; // с блока 200000

        // Связываем дерево:
        // consensus (0..199999) → pRight → auxpowConsensus (200000+)
        pConsensusRoot = &consensus;
        consensus.pLeft = NULL;
        consensus.pRight = &auxpowConsensus;
        auxpowConsensus.pLeft = &consensus;
        auxpowConsensus.pRight = NULL;

        // digishieldConsensus не используем отдельно (DigiShield включён глобально)
        digishieldConsensus = consensus;

        pchMessageStart[0] = 0x52;
        pchMessageStart[1] = 0x47;
        pchMessageStart[2] = 0x4d;
        pchMessageStart[3] = 0x01;

        nDefaultPort = 14030;
        nPruneAfterHeight = 100000;

        // MAIN genesis
        genesis = CreateGenesisBlock(1772064000, 132281, 0x1e0ffff0, 1, 100 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        assert(consensus.hashGenesisBlock == uint256S("0x165c122ffcd10871778d533cda132cbde2b487877ccb7b9edcfa2d4c71a5e7ef"));
        assert(genesis.hashMerkleRoot == uint256S("0xbd8e7111101c0d6a75516a1a3ea8c4292f5348169df0f1252adea9a4c0f684bc"));

        // seeds убираем
        vSeeds.clear();
        vFixedSeeds.clear();

        // твои префиксы
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 122);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 188);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0xB2)(0x47)(0x46).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0xB2)(0x43)(0x0C).convert_to_container<std::vector<unsigned char> >();
        bech32_hrp = "rgm";

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock}
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CTestNetParams() {
        strNetworkID = "test";

        consensus.nSubsidyHalvingInterval = 2102400; // ~4 года при 1 мин/блок
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;

        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.nQuantumSafeHeight = 5000; // PQ с SegWit (блок 5000)

        consensus.powLimit = uint256S("0x0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // --- RGM TESTNET ---
        consensus.nPowTargetTimespan = 60;
        consensus.nPowTargetSpacing = 60;
        consensus.nLwmaAveragingWindow = 45;
        consensus.nLwmaHeight = 1;
        consensus.fDigishieldDifficultyCalculation = true;

        // Testnet этапы (в ~10 раз быстрее mainnet для тестирования)
        // Порядок: Pool → SegWit → AuxPoW
        consensus.nPoolMiningPhaseHeight = 1000;
        consensus.nSegwitHeight = 5000;    // SegWit до AuxPoW!
        consensus.nAuxpowHeight = 20000;

        consensus.nCoinbaseMaturity = 30;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowAllowRGMMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;

        consensus.nRuleChangeActivationThreshold = 1512;
        consensus.nMinerConfirmationWindow = 2016;

        // TESTDUMMY выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout   = std::numeric_limits<int64_t>::max();

        // CSV выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout   = std::numeric_limits<int64_t>::max();

        // SegWit выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout   = std::numeric_limits<int64_t>::max();

        consensus.nMinimumChainWork = uint256();
        consensus.defaultAssumeValid = uint256();

        consensus.nAuxpowChainId = 0x5247;

        // RGM TESTNET: дерево consensus — переключение Legacy→AuxPoW
        consensus.fAllowLegacyBlocks = true;
        consensus.fStrictChainId = false;
        consensus.nHeightEffective = 0;

        auxpowConsensus = consensus;
        auxpowConsensus.fAllowLegacyBlocks = false;  // с блока 20000 legacy запрещены
        auxpowConsensus.fStrictChainId = true;
        auxpowConsensus.nHeightEffective = consensus.nAuxpowHeight;

        pConsensusRoot = &consensus;
        consensus.pLeft = NULL;
        consensus.pRight = &auxpowConsensus;
        auxpowConsensus.pLeft = &consensus;
        auxpowConsensus.pRight = NULL;

        digishieldConsensus = consensus;

        pchMessageStart[0] = 0x52;
        pchMessageStart[1] = 0x47;
        pchMessageStart[2] = 0x4d;
        pchMessageStart[3] = 0x02;

        nDefaultPort = 24030;
        nPruneAfterHeight = 1000;

        // TESTNET genesis
        genesis = CreateGenesisBlock(1772065000, 43076, 0x1f00ffff, 1, 100 * COIN);

        consensus.hashGenesisBlock = genesis.GetHash();
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        assert(consensus.hashGenesisBlock == uint256S("0xd09e500329e656f4fe1e1dc2a398b2162b72d76163275bc6804f4bc1cf196035"));
        assert(genesis.hashMerkleRoot == uint256S("0xbd8e7111101c0d6a75516a1a3ea8c4292f5348169df0f1252adea9a4c0f684bc"));


        vSeeds.clear();
        vFixedSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 122);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 188);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0xB2)(0x47)(0x46).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0xB2)(0x43)(0x0C).convert_to_container<std::vector<unsigned char> >();
        bech32_hrp = "trgm";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;



         checkpointData = {
            {
                {0, consensus.hashGenesisBlock}
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };


    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
private:
    Consensus::Params digishieldConsensus;
    Consensus::Params auxpowConsensus;

public:
    CRegTestParams() {
        strNetworkID = "regtest";

        consensus.nSubsidyHalvingInterval = 150;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;

        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.nQuantumSafeHeight = 50; // PQ с SegWit (блок 50)

        consensus.powLimit = uint256S("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        // RGM REGTEST: максимально быстрое тестирование
        consensus.nPowTargetTimespan = 1;         // пересчёт каждую секунду
        consensus.nPowTargetSpacing = 1;          // блок каждую секунду
        consensus.nLwmaAveragingWindow = 1;      // маленькое окно для быстрой реакции
        consensus.fDigishieldDifficultyCalculation = false; // выключен — fPowNoRetargeting=true всё равно

        consensus.nCoinbaseMaturity = 1;          // монеты сразу доступны (для тестов)
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowAllowRGMMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;       // сложность не меняется — быстрое тестирование

        consensus.nRuleChangeActivationThreshold = 108;
        consensus.nMinerConfirmationWindow = 144;

        // TESTDUMMY выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout   = std::numeric_limits<int64_t>::max();

        // CSV выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout   = std::numeric_limits<int64_t>::max();

        // SegWit выключен
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = std::numeric_limits<int64_t>::max();
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout   = std::numeric_limits<int64_t>::max();

        consensus.nMinimumChainWork = uint256();
        consensus.defaultAssumeValid = uint256();

        // RGM REGTEST: этапы запуска — очень маленькие высоты для проверки кода
        // Порядок: Pool → SegWit → AuxPoW (как mainnet/testnet)
        consensus.nPoolMiningPhaseHeight = 10;   // pool phase через 10 блоков
        consensus.nSegwitHeight          = 50;   // SegWit через 50 блоков (до AuxPoW!)
        consensus.nAuxpowHeight          = 100;  // AuxPoW через 100 блоков
        consensus.nSubsidyHalvingInterval = 150; // халвинг через 150 блоков

        consensus.nAuxpowChainId = 0x5247;

        // RGM REGTEST: дерево consensus — тестируем переключение Legacy→AuxPoW
        consensus.fAllowLegacyBlocks = true;
        consensus.fStrictChainId = false;
        consensus.nHeightEffective = 0;

        auxpowConsensus = consensus;
        auxpowConsensus.fAllowLegacyBlocks = false; // с блока 100 legacy запрещены
        auxpowConsensus.fStrictChainId = false;     // regtest: не строго
        auxpowConsensus.nHeightEffective = consensus.nAuxpowHeight; // блок 100

        pConsensusRoot = &consensus;
        consensus.pLeft = NULL;
        consensus.pRight = &auxpowConsensus;
        auxpowConsensus.pLeft = &consensus;
        auxpowConsensus.pRight = NULL;

        digishieldConsensus = consensus;

        pchMessageStart[0] = 0x52;
        pchMessageStart[1] = 0x47;
        pchMessageStart[2] = 0x4d;
        pchMessageStart[3] = 0x03;

        nDefaultPort = 34030;
        nPruneAfterHeight = 1000;

        // REGTEST genesis
        genesis = CreateGenesisBlock(1772066000, 1, 0x207fffff, 1, 100 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        auxpowConsensus.hashGenesisBlock = consensus.hashGenesisBlock;

        assert(consensus.hashGenesisBlock == uint256S("0x12e96208094ffa758734ff98aa977505c58b535b561c47fa5e77556e2f570dff"));
        assert(genesis.hashMerkleRoot == uint256S("0xbd8e7111101c0d6a75516a1a3ea8c4292f5348169df0f1252adea9a4c0f684bc"));

        vSeeds.clear();
        vFixedSeeds.clear();

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;


        checkpointData = {
            {
                {0, consensus.hashGenesisBlock}
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };


        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 122);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 188);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0xB2)(0x47)(0x46).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0xB2)(0x43)(0x0C).convert_to_container<std::vector<unsigned char> >();
        bech32_hrp = "rrgm";
    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

const Consensus::Params *Consensus::Params::GetConsensus(uint32_t nTargetHeight) const {
    if (nTargetHeight < this->nHeightEffective && this->pLeft != NULL) {
        return this->pLeft->GetConsensus(nTargetHeight);
    // RGM пункт 2: >= вместо > — убираем двусмысленность на граничной высоте.
    // Блок ровно на nAuxpowHeight должен использовать auxpowConsensus, не legacy.
    } else if (this->pRight != NULL && nTargetHeight >= this->pRight->nHeightEffective) {
        return this->pRight->GetConsensus(nTargetHeight);
    }

    return this;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
        return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
        return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}
