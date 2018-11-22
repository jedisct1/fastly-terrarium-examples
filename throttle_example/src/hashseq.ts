namespace HashSeq {
    interface IMask {
        m0: number;
        m1: number;
    }

    export interface ISolution {
        s0: number;
        s1: number;
    }

    function permute(state: Uint32Array): void {
        state[0] += state[4]; state[12] = (((state[12] ^ state[0]) >>> 16) | ((state[12] ^ state[0]) << (32 - 16))); state[8] += state[12]; state[4] = (((state[4] ^ state[8]) >>> 12) | ((state[4] ^ state[8]) << (32 - 12))); state[0] += state[4]; state[12] = (((state[12] ^ state[0]) >>> 8) | ((state[12] ^ state[0]) << (32 - 8))); state[8] += state[12]; state[4] = (((state[4] ^ state[8]) >>> 7) | ((state[4] ^ state[8]) << (32 - 7)));
        state[1] += state[5]; state[13] = (((state[13] ^ state[1]) >>> 16) | ((state[13] ^ state[1]) << (32 - 16))); state[9] += state[13]; state[5] = (((state[5] ^ state[9]) >>> 12) | ((state[5] ^ state[9]) << (32 - 12))); state[1] += state[5]; state[13] = (((state[13] ^ state[1]) >>> 8) | ((state[13] ^ state[1]) << (32 - 8))); state[9] += state[13]; state[5] = (((state[5] ^ state[9]) >>> 7) | ((state[5] ^ state[9]) << (32 - 7)));
        state[2] += state[6]; state[14] = (((state[14] ^ state[2]) >>> 16) | ((state[14] ^ state[2]) << (32 - 16))); state[10] += state[14]; state[6] = (((state[6] ^ state[10]) >>> 12) | ((state[6] ^ state[10]) << (32 - 12))); state[2] += state[6]; state[14] = (((state[14] ^ state[2]) >>> 8) | ((state[14] ^ state[2]) << (32 - 8))); state[10] += state[14]; state[6] = (((state[6] ^ state[10]) >>> 7) | ((state[6] ^ state[10]) << (32 - 7)));
        state[3] += state[7]; state[15] = (((state[15] ^ state[3]) >>> 16) | ((state[15] ^ state[3]) << (32 - 16))); state[11] += state[15]; state[7] = (((state[7] ^ state[11]) >>> 12) | ((state[7] ^ state[11]) << (32 - 12))); state[3] += state[7]; state[15] = (((state[15] ^ state[3]) >>> 8) | ((state[15] ^ state[3]) << (32 - 8))); state[11] += state[15]; state[7] = (((state[7] ^ state[11]) >>> 7) | ((state[7] ^ state[11]) << (32 - 7)));

        state[0] += state[5]; state[15] = (((state[15] ^ state[0]) >>> 16) | ((state[15] ^ state[0]) << (32 - 16))); state[10] += state[15]; state[5] = (((state[5] ^ state[10]) >>> 12) | ((state[5] ^ state[10]) << (32 - 12))); state[0] += state[5]; state[15] = (((state[15] ^ state[0]) >>> 8) | ((state[15] ^ state[0]) << (32 - 8))); state[10] += state[15]; state[5] = (((state[5] ^ state[10]) >>> 7) | ((state[5] ^ state[10]) << (32 - 7)));
        state[1] += state[6]; state[12] = (((state[12] ^ state[1]) >>> 16) | ((state[12] ^ state[1]) << (32 - 16))); state[11] += state[12]; state[6] = (((state[6] ^ state[11]) >>> 12) | ((state[6] ^ state[11]) << (32 - 12))); state[1] += state[6]; state[12] = (((state[12] ^ state[1]) >>> 8) | ((state[12] ^ state[1]) << (32 - 8))); state[11] += state[12]; state[6] = (((state[6] ^ state[11]) >>> 7) | ((state[6] ^ state[11]) << (32 - 7)));
        state[2] += state[7]; state[13] = (((state[13] ^ state[2]) >>> 16) | ((state[13] ^ state[2]) << (32 - 16))); state[8] += state[13]; state[7] = (((state[7] ^ state[8]) >>> 12) | ((state[7] ^ state[8]) << (32 - 12))); state[2] += state[7]; state[13] = (((state[13] ^ state[2]) >>> 8) | ((state[13] ^ state[2]) << (32 - 8))); state[8] += state[13]; state[7] = (((state[7] ^ state[8]) >>> 7) | ((state[7] ^ state[8]) << (32 - 7)));
        state[3] += state[4]; state[14] = (((state[14] ^ state[3]) >>> 16) | ((state[14] ^ state[3]) << (32 - 16))); state[9] += state[14]; state[4] = (((state[4] ^ state[9]) >>> 12) | ((state[4] ^ state[9]) << (32 - 12))); state[3] += state[4]; state[14] = (((state[14] ^ state[3]) >>> 8) | ((state[14] ^ state[3]) << (32 - 8))); state[9] += state[14]; state[4] = (((state[4] ^ state[9]) >>> 7) | ((state[4] ^ state[9]) << (32 - 7)));
    }

    function hash_init(state: Uint32Array, suffix: Uint32Array, level: number, iteration: number): void {
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;

        state[8] = state[0] ^ suffix[0];
        state[9] = state[1] ^ suffix[1];
        state[10] = state[2] ^ suffix[2];
        state[11] = state[3] ^ suffix[3];
        state[12] = state[4] ^ suffix[4];
        state[13] = state[5] ^ suffix[5];
        state[14] = state[6] ^ suffix[6];
        state[15] = state[7] ^ suffix[7];

        state[7] ^= ((level << 16) | iteration);
    }

    function hash_try(ostate: Uint32Array, istate: Uint32Array, proposal: ISolution, mask: IMask): boolean {
        istate[0] = 0x6a09e667 ^ proposal.s0;
        istate[1] = 0xbb67ae85 ^ proposal.s1;
        ostate.set(istate);
        for (let i = 0; i < 6; i++) {
            permute(ostate);
        }
        let f0 = ostate[0];
        let f1 = ostate[1];
        for (let i = 2; i < 16; i += 2) {
            f0 ^= ostate[i];
            f1 ^= ostate[i + 1];
        }
        return ((f0 & mask.m0) | (f1 & mask.m1)) === 0;
    }

    function mask_from_level(mask: IMask, level: number): void {
        if (level > 32) {
            mask.m0 = ~0;
            mask.m1 = (1 << (level - 32)) - 1 | 0;
        } else {
            mask.m1 = 0;
            mask.m0 = (1 << level) - 1 | 0;
        }
    }

    function solve1(suffix: Uint32Array, level: number, iteration: number): ISolution {
        const istate = new Uint32Array(16);
        const ostate = new Uint32Array(16);
        const mask = { m0: 0, m1: 0 };
        hash_init(istate, suffix, level, iteration);
        mask_from_level(mask, level);
        const proposal = { s0: 0, s1: 0 };
        while (!hash_try(ostate, istate, proposal, mask)) {
            proposal.s0 = (proposal.s0 + 1) | 0;
            if (proposal.s0 === 0) {
                proposal.s1 = (proposal.s1 + 1) | 0;
            }
        }
        suffix.set(ostate.slice(8));
        return proposal;
    }

    function verify1(proposal: ISolution, suffix: Uint32Array, level: number, iteration: number): boolean {
        const state = new Uint32Array(16);
        const mask = { m0: 0, m1: 0 };
        hash_init(state, suffix, level, iteration);
        mask_from_level(mask, level);
        if (hash_try(state, state, proposal, mask)) {
            suffix.set(state.slice(8));
            return true;
        }
        return false;
    }

    export function solve(suffix: Uint32Array, levelFirst: number, levelLast: number, iterations: number): ISolution[] {
        const suffix2 = suffix.slice();
        const solutions = [];
        for (let level = levelFirst; level <= levelLast; level++) {
            for (let iteration = 0; iteration < iterations; iteration++) {
                solutions.push(solve1(suffix2, level, iteration));
            }
        }
        return solutions;
    }

    export function solveAsync(callback: (solutions: ISolution[]) => void, suffix: Uint32Array, levelFirst: number, levelLast: number, iterations: number): void {
        const suffix2 = suffix.slice();
        const solutions: ISolution[] = [];

        function solve1Async(level: number, iteration: number): void {
            solutions.push(solve1(suffix2, level, iteration));
            if (++iteration >= iterations) {
                iteration = 0;
                if (++level > levelLast) {
                    return callback(solutions);
                }
            }
            setTimeout(() => { solve1Async(level, iteration); }, 0);
        }
        solve1Async(levelFirst, 0);
    }

    export function verify(solutions: ISolution[], suffix: Uint32Array, levelFirst: number, levelLast: number, iterations: number): boolean {
        const suffix2 = suffix.slice();
        let i = 0;
        for (let level = levelFirst; level <= levelLast; level++) {
            for (let iteration = 0; iteration < iterations; iteration++) {
                if (!verify1(solutions[i++], suffix2, level, iteration)) {
                    return false;
                }
            }
        }
        return true;
    }
}
