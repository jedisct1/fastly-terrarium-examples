
/*
 * A simple hashcash-like proof-of-work, using the BLAKE2S internal permutation.
 *
 * This implementation uses only 32-bit registers in order to be
 * efficient on constrained devices and to be straightforward to
 * port to Javascript.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "hashseq.h"

typedef struct Mask_ {
    uint32_t m0;
    uint32_t m1;
} Mask;

static inline void permute(uint32_t state[16])
{
    G(state[0], state[4], state[8], state[12]);
    G(state[1], state[5], state[9], state[13]);
    G(state[2], state[6], state[10], state[14]);
    G(state[3], state[7], state[11], state[15]);

    G(state[0], state[5], state[10], state[15]);
    G(state[1], state[6], state[11], state[12]);
    G(state[2], state[7], state[8], state[13]);
    G(state[3], state[4], state[9], state[14]);
}

static inline void hash_init(uint32_t state[16], const uint32_t suffix[8], uint32_t level,
                             uint32_t iteration)
{
    int i;

    memcpy(&state[0], IV, 8 * sizeof state[0]);
    state[7] ^= (level << 16) | iteration;
    for (i = 0; i < 8; i++) {
        state[8 + i] = IV[i] ^ suffix[i];
    }
}

static int hash_try(uint32_t ostate[16], uint32_t istate[16], const HashSeqSolution *proposal,
                    const Mask *mask)
{
    uint32_t f0, f1;
    int      i;

    istate[0] = IV[0] ^ proposal->s0;
    istate[1] = IV[1] ^ proposal->s1;
    memcpy(ostate, istate, 16 * sizeof ostate[0]);
    for (i = 0; i < 6; i++) {
        permute(ostate);
    }
    f0 = ostate[0];
    f1 = ostate[1];
    for (i = 2; i < 16; i += 2) {
        f0 ^= ostate[i];
        f1 ^= ostate[i + 1];
    }
    return ((f0 & mask->m0) | (f1 & mask->m1)) == 0U;
}

static void mask_from_level(Mask *mask, uint32_t level)
{
    if (level > 32U) {
        mask->m0 = ~0U;
        mask->m1 = (1U << (level - 32)) - 1U;
    } else {
        mask->m1 = 0U;
        mask->m0 = (1U << level) - 1U;
    }
}

static int solve1(HashSeqSolution *solution, uint32_t suffix[8], uint32_t level, uint32_t iteration)
{
    uint32_t        istate[16], ostate[16];
    Mask            mask;
    HashSeqSolution proposal;

    hash_init(istate, suffix, level, iteration);
    mask_from_level(&mask, level);
    proposal.s0 = proposal.s1 = 0U;
    while (hash_try(ostate, istate, &proposal, &mask) == 0) {
        if (++proposal.s0 == 0U) {
            proposal.s1++;
        }
    }
    memcpy(suffix, &ostate[8], 8 * sizeof ostate[0]);
    memcpy(solution, &proposal, sizeof *solution);

    return 0;
}

static int verify1(const HashSeqSolution *proposal, uint32_t suffix[8], uint32_t level,
                   uint32_t iteration)
{
    uint32_t state[16];
    Mask     mask;

    hash_init(state, suffix, level, iteration);
    mask_from_level(&mask, level);
    if (hash_try(state, state, proposal, &mask)) {
        memcpy(suffix, &state[8], 8 * sizeof state[0]);
        return 1;
    }
    return 0;
}

int hashseq_solve(HashSeqSolution *solutions, const uint32_t suffix[8], uint32_t level_first,
                  uint32_t level_last, uint32_t iterations)
{
    uint32_t suffix_[8];
    uint32_t level, iteration;
    int      i = 0;

    memcpy(suffix_, suffix, sizeof suffix_);
    for (level = level_first; level <= level_last; level++) {
        for (iteration = 0; iteration < iterations; iteration++) {
            if (solve1(&solutions[i++], suffix_, level, iteration) != 0) {
                return -1;
            }
        }
    }
    return 0;
}

int hashseq_verify(const HashSeqSolution *solutions, const uint32_t suffix[8], uint32_t level_first,
                   uint32_t level_last, uint32_t iterations)
{
    uint32_t suffix_[8];
    uint32_t level, iteration;
    int      i = 0;

    memcpy(suffix_, suffix, sizeof suffix_);
    for (level = level_first; level <= level_last; level++) {
        for (iteration = 0; iteration < iterations; iteration++) {
            if (verify1(&solutions[i++], suffix_, level, iteration) == 0) {
                return 0;
            }
        }
    }
    return 1;
}
