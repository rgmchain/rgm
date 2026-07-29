// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "auxpow.h"
#include "arith_uint256.h"
#include "chain.h"
#include "rgm.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"

// Determine if for the given block, a min difficulty setting applies
bool AllowMinDifficultyForBlock(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    // chain does not allow minimum difficulty blocks
    if (!params.fPowAllowMinDifficultyBlocks)
        return false;

    // Allow minimum difficulty if block time is too far in the future
    return (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2);
}

// LWMA difficulty algorithm
unsigned int LwmaCalculateNextWorkRequired(const CBlockIndex* pindexLast, const Consensus::Params& params)
{
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    // Not enough blocks yet -> stay at powLimit
    if (pindexLast == nullptr || pindexLast->nHeight < params.nLwmaAveragingWindow)
        return bnPowLimit.GetCompact();

    const int64_t T = params.nPowTargetSpacing;
    const int64_t N = params.nLwmaAveragingWindow;

    // k = T * N * (N + 1) / 2
    const int64_t k = T * N * (N + 1) / 2;

    int64_t sumWeightedSolvetimes = 0;

    arith_uint256 avgTarget;
    avgTarget.SetCompact(pindexLast->nBits);

    const CBlockIndex* block = pindexLast;

    for (int64_t i = N; i >= 1; --i) {
        const CBlockIndex* prev = block->pprev;
        if (prev == nullptr)
            break;

        int64_t solvetime = block->GetBlockTime() - prev->GetBlockTime();

        // Clamp solvetime to reduce extreme jumps / manipulation
        if (solvetime > 6 * T) solvetime = 6 * T;
        if (solvetime < -6 * T) solvetime = -6 * T;

        sumWeightedSolvetimes += solvetime * i;

        arith_uint256 target;
        target.SetCompact(block->nBits);

        // Smooth average of targets
        avgTarget = (avgTarget * (N - 1) + target) / N;

        block = prev;
    }

    // Prevent too-small weighted time
    if (sumWeightedSolvetimes < k / 10)
        sumWeightedSolvetimes = k / 10;

    arith_uint256 nextTarget = avgTarget;
    nextTarget *= sumWeightedSolvetimes;
    nextTarget /= k;

    if (nextTarget == 0 || nextTarget > bnPowLimit)
        nextTarget = bnPowLimit;

    return nextTarget.GetCompact();
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    const unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    // No retargeting (regtest-like mode)
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // --- RGM: аварийный сброс сложности при застревании сети (хардфорк) ---
    // Если правило активно (высота следующего блока >= nEmergencyMinDiffHeight)
    // и с предыдущего блока прошло больше nEmergencyMinDiffTimeout секунд —
    // разрешаем блок минимальной сложности. Это спасает цепь, когда крупный
    // майнер разгоняет сложность и уходит, а честного хешрейта не хватает даже
    // на один блок. Таймаут берётся больше окна MAX_FUTURE_BLOCK_TIME (2 ч),
    // поэтому на здоровой сети правило не срабатывает и не эксплуатируется:
    // время блока нельзя задрать в будущее настолько, чтобы искусственно
    // вызвать сброс. Один такой блок через DigiShield каскадно возвращает
    // сложность к минимуму, после чего она отрастает обратно под реальный
    // хешрейт (не быстрее +33%/блок).
    if (params.nEmergencyMinDiffHeight >= 0 &&
        pindexLast->nHeight + 1 >= params.nEmergencyMinDiffHeight &&
        pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nEmergencyMinDiffTimeout) {
        return nProofOfWorkLimit;
    }

    // --- RGM: минимальная сложность для testnet ---
    if (AllowMinDifficultyForBlock(pindexLast, pblock, params)) {
        // Dogecoin-style: проверяем и DigiShield вариант
        if (AllowRGMMinDifficultyForBlock(pindexLast, pblock, params))
            return nProofOfWorkLimit;
        if (params.fPowAllowMinDifficultyBlocks)
            return nProofOfWorkLimit;
    }

    // --- RGM: выбор алгоритма сложности ---
    // Если DigiShield включён (защита от асиков/мультипулов) — используем его
    // поверх LWMA для более агрессивного сглаживания
    if (params.fDigishieldDifficultyCalculation) {
        // DigiShield работает как быстрый retarget каждый блок
        // Используем CalculateRGMNextWorkRequired из dogecoin.cpp
        int64_t nFirstBlockTime = pindexLast->pprev
            ? pindexLast->pprev->GetBlockTime()
            : pindexLast->GetBlockTime();
        return CalculateRGMNextWorkRequired(pindexLast, nFirstBlockTime, params);
    }

    // Иначе — чистый LWMA
    return LwmaCalculateNextWorkRequired(pindexLast, params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4)
        nActualTimespan = params.nPowTargetTimespan / 4;
    if (nActualTimespan > params.nPowTargetTimespan * 4)
        nActualTimespan = params.nPowTargetTimespan * 4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
