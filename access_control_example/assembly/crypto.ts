// tslint:disable-next-line:no-reference
/// <reference path="../node_modules/assemblyscript/index.d.ts" />

import 'allocator/tlsf';
import { LOAD, STORE } from 'internal/arraybuffer';
import { precompBase } from './precomp';
export { memory };

@inline function setU8(t: Uint8Array, s: Uint8Array, o: isize = 0): void {
    for (let i: isize = 0, len = s.length; i < len; ++i) {
        t[i + o] = s[i];
    }
}

// SHA512

@inline function Sigma0(x: u64): u64 {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

@inline function Sigma1(x: u64): u64 {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

@inline function sigma0(x: u64): u64 {
    return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
}

@inline function sigma1(x: u64): u64 {
    return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
}

@inline function Ch(x: u64, y: u64, z: u64): u64 {
    return (x & y) ^ (~x & z);
}

@inline function Maj(x: u64, y: u64, z: u64): u64 {
    return (x & y) ^ (x & z) ^ (y & z);
}

function load64(x: Uint8Array, offset: isize): u64 {
    return LOAD<u64>(x.buffer, 0, offset);
}

function store64(x: Uint8Array, offset: isize, u: u64): void {
    STORE<u64>(x.buffer, 0, u, offset);
}

const K: u64[] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

function _hashblocks(st: Uint8Array, m: Uint8Array, n: isize): isize {
    let z = new Uint64Array(8),
        b = new Uint64Array(8),
        a = new Uint64Array(8),
        w = new Uint64Array(16),
        t: u64;

    for (let i = 0; i < 8; ++i) {
        z[i] = a[i] = load64(st, i << 3);
    }
    let pos = 0;
    while (n >= 128) {
        for (let i = 0; i < 16; ++i) {
            w[i] = load64(m, (i << 3) + pos);
        }
        for (let i = 0; i < 80; ++i) {
            for (let j = 0; j < 8; ++j) {
                b[j] = a[j];
            }
            t = a[7] + Sigma1(a[4]) + Ch(a[4], a[5], a[6]) + K[i] + w[i & 15];
            b[7] = t + Sigma0(a[0]) + Maj(a[0], a[1], a[2]);
            b[3] += t;
            for (let j = 0; j < 8; ++j) {
                a[(j + 1) & 7] = b[j];
            }
            if ((i & 15) === 15) {
                for (let j = 0; j < 16; ++j) {
                    w[j] += w[(j + 9) & 15] + sigma0(w[(j + 1) & 15]) + sigma1(w[(j + 14) & 15]);
                }
            }
        }
        for (let i = 0; i < 8; ++i) {
            a[i] += z[i];
            z[i] = a[i];
        }
        pos += 128;
        n -= 128;
    }
    for (let i = 0; i < 8; ++i) {
        store64(st, i << 3, z[i]);
    }
    return n;
}

const iv_: u8[] = [
    0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b,
    0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1,
    0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f,
    0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79,
];

let iv = new Uint8Array(64);
for (let i = 0; i < 64; ++i) {
    iv[i] = iv_[i];
}

function _hashInit(): Uint8Array {
    let st = new Uint8Array(64 + 128 + 8 * 2);

    for (let i = 0; i < 64; ++i) {
        st[i] = iv[i];
    }
    return st;
}

function _hashUpdate(st: Uint8Array, m: Uint8Array, n: isize, r: isize): isize {
    let w = st.subarray(64);
    let pos = 0;
    let av = 128 - r;
    let tc = min(n, av);

    setU8(w, m.subarray(0, tc), r);
    r += tc;
    n -= tc;
    pos += tc;
    if (r === 128) {
        _hashblocks(st, w, 128);
        r = 0;
    }
    if (r === 0 && n > 0) {
        let rb = _hashblocks(st, m.subarray(pos), n);
        if (rb > 0) {
            setU8(w, m.subarray(pos + n - rb), r);
            r += rb;
        }
    }
    return r;
}

function _hashFinal(st: Uint8Array, out: Uint8Array, t: isize, r: isize): void {
    let w = st.subarray(64);
    let x = new Uint8Array(256);

    setU8(x, w.subarray(0, r));
    x[r] = 128;
    r = 256 - (isize(r < 112) << 7);
    x[r - 9] = 0;
    store64(x, r - 8, t << 3);
    _hashblocks(st, x, r);
    for (let i = 0; i < 64; ++i) {
        out[i] = st[i];
    }
}

function _hash(out: Uint8Array, m: Uint8Array, n: isize): void {
    let st = _hashInit();
    let r = _hashUpdate(st, m, n, 0);

    _hashFinal(st, out, n, r);
}

// HMAC

function _hmac(m: Uint8Array, k: Uint8Array): Uint8Array {
    let b = new Uint8Array(256);
    let ib = b.subarray(128);
    if (k.length > 128) {
        k = hash(k);
    }
    setU8(b, k);
    for (let i = 0; i < 128; ++i) {
        b[i] ^= 0x5c;
    }
    setU8(ib, k);
    for (let i = 0; i < 128; ++i) {
        ib[i] ^= 0x36;
    }
    let st = _hashInit();
    let r = _hashUpdate(st, ib, 128, 0);
    r = _hashUpdate(st, m, m.length, r);
    _hashFinal(st, b, 128 + m.length, r);

    return hash(b);
}

// helpers

function verify32(x: Uint8Array, y: Uint8Array): bool {
    let d: u8 = 0;

    for (let i = 0; i < 32; ++i) {
        d |= x[i] ^ y[i];
    }
    return d === 0;
}

function allZeros(x: Uint8Array): bool {
    let len = x.length;
    let c: u8 = 0;
    for (let i = 0; i < len; ++i) {
        c |= x[i];
    }
    return c === 0;
}

// mod(2^252 + 27742317777372353535851937790883648495) field arithmetic

let _L: Int64Array = new Int64Array(32);
_L[0] = 237;
_L[1] = 211;
_L[2] = 245;
_L[3] = 92;
_L[4] = 26;
_L[5] = 99;
_L[6] = 18;
_L[7] = 88;
_L[8] = 214;
_L[9] = 156;
_L[10] = 247;
_L[11] = 162;
_L[12] = 222;
_L[13] = 249;
_L[14] = 222;
_L[15] = 20;
_L[31] = 16;

@inline function scn(): Int64Array {
    return new Int64Array(64);
}

function scModL(r: Uint8Array, x: Int64Array): void {
    let carry: i64;

    for (let i = 63; i >= 32; --i) {
        carry = 0;
        let k = i - 12;
        let xi = x[i];
        for (let j = i - 32; j < k; ++j) {
            let xj = x[j] + carry - 16 * xi * _L[j - (i - 32)];
            carry = (xj + 128) >> 8;
            x[j] = xj - carry * 256;
        }
        x[k] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (let j = 0; j < 32; ++j) {
        let xj = x[j] + carry - (x[31] >> 4) * _L[j];
        carry = xj >> 8;
        x[j] = xj & 255;
    }
    for (let j = 0; j < 32; ++j) {
        x[j] -= carry * _L[j];
    }
    for (let i = 0; i < 32; ++i) {
        let xi = x[i];
        x[i + 1] += xi >> 8;
        r[i] = xi as u8;
    }
}

function scReduce(r: Uint8Array): void {
    let x = new Int64Array(64);

    for (let i = 0; i < 64; ++i) {
        x[i] = r[i];
        r[i] = 0;
    }
    scModL(r, x);
}

function scCarry(a: Int64Array): void {
    let carry: i64 = 0;
    for (let i = 0; i < 64; ++i) {
        let c = a[i] + carry;
        a[i] = c & 0xff;
        carry = (c >>> 8)
    }
    if (carry > 0) {
        throw new Error('overflow');
    }
}

function scMult(o: Int64Array, a: Int64Array, b: Int64Array): void {
    let r = new Uint8Array(32);
    let t = new Int64Array(64);

    for (let i = 0; i < 32; ++i) {
        let ai = a[i];
        for (let j = 0; j < 32; ++j) {
            t[i + j] += ai * b[j];
        }
    }
    scCarry(t);
    scModL(r, t);
    for (let i = 0; i < 32; ++i) {
        o[i] = r[i];
    }
    for (let i = 32; i < 64; ++i) {
        o[i] = 0;
    }
}

function scSq(o: Int64Array, a: Int64Array): void {
    scMult(o, a, a);
}

function scSqMult(y: Int64Array, squarings: isize, x: Int64Array): void {
    for (let i = 0; i < squarings; ++i) {
        scSq(y, y);
    }
    scMult(y, y, x);
}

function scInverse(s: Uint8Array): Uint8Array {
    let res = new Uint8Array(32);
    let _1 = scn();
    for (let i = 0; i < 32; ++i) {
        _1[i] = s[i];
    }
    let _10 = scn(),
        _100 = scn(),
        _11 = scn(),
        _101 = scn(),
        _111 = scn(),
        _1001 = scn(),
        _1011 = scn(),
        _1111 = scn(),
        y = scn();

    scSq(_10, _1);
    scSq(_100, _10);
    scMult(_11, _10, _1);
    scMult(_101, _10, _11);
    scMult(_111, _10, _101);
    scMult(_1001, _10, _111);
    scMult(_1011, _10, _1001);
    scMult(_1111, _100, _1011);
    scMult(y, _1111, _1);

    scSqMult(y, 123 + 3, _101);
    scSqMult(y, 2 + 2, _11);
    scSqMult(y, 1 + 4, _1111);
    scSqMult(y, 1 + 4, _1111);
    scSqMult(y, 4, _1001);
    scSqMult(y, 2, _11);
    scSqMult(y, 1 + 4, _1111);
    scSqMult(y, 1 + 3, _101);
    scSqMult(y, 3 + 3, _101);
    scSqMult(y, 3, _111);
    scSqMult(y, 1 + 4, _1111);
    scSqMult(y, 2 + 3, _111);
    scSqMult(y, 2 + 2, _11);
    scSqMult(y, 1 + 4, _1011);
    scSqMult(y, 2 + 4, _1011);
    scSqMult(y, 6 + 4, _1001);
    scSqMult(y, 2 + 2, _11);
    scSqMult(y, 3 + 2, _11);
    scSqMult(y, 3 + 2, _11);
    scSqMult(y, 1 + 4, _1001);
    scSqMult(y, 1 + 3, _111);
    scSqMult(y, 2 + 4, _1111);
    scSqMult(y, 1 + 4, _1011);
    scSqMult(y, 3, _101);
    scSqMult(y, 2 + 4, _1111);
    scSqMult(y, 3, _101);
    scSqMult(y, 1 + 2, _11);

    for (let i = 0; i < 32; ++i) {
        y[i + 1] += y[i] >> 8;
        res[i] = y[i] as u8;
    }
    return res;
}

@inline function scClamp(s: Uint8Array): void {
    s[0] &= 248;
    s[31] = (s[31] & 127) | 64;
}

function scAdd(a: Uint8Array, b: Uint8Array): void {
    let c: u32 = 0;
    for (let i = 0, len = a.length; i < len; i++) {
        c += (a[i] as u32) + (b[i] as u32);
        a[i] = c as u8;
        c >>= 8;
    }
}

function scSub(a: Uint8Array, b: Uint8Array): void {
    let c: u32 = 0;
    for (let i = 0, len = a.length; i < len; i++) {
        c = (a[i] as u32) - (b[i] as u32) - c;
        a[i] = c as u8;
        c = (c >> 8) & 1;
    }
}

// mod(2^255-19) field arithmetic - Doesn't use 51-bit limbs yet to keep the
// code short and simple

@inline function fe25519n(): Int64Array {
    return new Int64Array(16);
}

function fe25519(init: i64[]): Int64Array {
    let r = new Int64Array(16);

    for (let i = 0, len = init.length; i < len; ++i) {
        r[i] = init[i];
    }
    return r;
}

let fe25519_0 = fe25519n();
let fe25519_1 = fe25519([1]);

let D = fe25519([
    0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
    0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203,
]);

let D2 = fe25519([
    0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
    0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406,
]);

let SQRTM1 = fe25519([
    0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
    0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83,
]);

let SQRTADM1 = fe25519([
    0x2e1b, 0x497b, 0xf6a0, 0x7e97, 0x54bd, 0x1b78, 0x8e0c, 0xaf9d,
    0xd1fd, 0x31f5, 0xfcc9, 0x0f3c, 0x48ac, 0x2b83, 0x31bf, 0x3769,
]);

let INVSQRTAMD = fe25519([
    0x40ea, 0x805d, 0xfdaa, 0x99c8, 0x72be, 0x5a41, 0x1617, 0x9d2f,
    0xd840, 0xfe01, 0x7b91, 0x16c2, 0xfca2, 0xcfaf, 0x8905, 0x786c,
]);

let ONEMSQD = fe25519([
    0xc176, 0x945f, 0x09c1, 0xe27c, 0x350f, 0xcd5e, 0xa138, 0x2c81,
    0xdfe4, 0xbe70, 0xabdd, 0x9994, 0xe0d7, 0xb2b3, 0x72a8, 0x0290,
]);

let SQDMONE = fe25519([
    0x4d20, 0x44ed, 0x5aaa, 0x31ad, 0x1999, 0xb01e, 0x4a2c, 0xd29e,
    0x4eeb, 0x529b, 0xd32f, 0x4cdc, 0x2241, 0xf66c, 0xb37a, 0x5968,
]);

@inline function fe25519Copy(r: Int64Array, a: Int64Array): void {
    r[0] = unchecked(a[0]);
    r[1] = unchecked(a[1]);
    r[2] = unchecked(a[2]);
    r[3] = unchecked(a[3]);
    r[4] = unchecked(a[4]);
    r[5] = unchecked(a[5]);
    r[6] = unchecked(a[6]);
    r[7] = unchecked(a[7]);
    r[8] = unchecked(a[8]);
    r[9] = unchecked(a[9]);
    r[10] = unchecked(a[10]);
    r[11] = unchecked(a[11]);
    r[12] = unchecked(a[12]);
    r[13] = unchecked(a[13]);
    r[14] = unchecked(a[14]);
    r[15] = unchecked(a[15]);
}

@inline function fe25519Cmov(p: Int64Array, q: Int64Array, b: i64): void {
    let mask = ~(b - 1);
    p[0] ^= (unchecked(p[0]) ^ unchecked(q[0])) & mask;
    p[1] ^= (unchecked(p[1]) ^ unchecked(q[1])) & mask;
    p[2] ^= (unchecked(p[2]) ^ unchecked(q[2])) & mask;
    p[3] ^= (unchecked(p[3]) ^ unchecked(q[3])) & mask;
    p[4] ^= (unchecked(p[4]) ^ unchecked(q[4])) & mask;
    p[5] ^= (unchecked(p[5]) ^ unchecked(q[5])) & mask;
    p[6] ^= (unchecked(p[6]) ^ unchecked(q[6])) & mask;
    p[7] ^= (unchecked(p[7]) ^ unchecked(q[7])) & mask;
    p[8] ^= (unchecked(p[8]) ^ unchecked(q[8])) & mask;
    p[9] ^= (unchecked(p[9]) ^ unchecked(q[9])) & mask;
    p[10] ^= (unchecked(p[10]) ^ unchecked(q[10])) & mask;
    p[11] ^= (unchecked(p[11]) ^ unchecked(q[11])) & mask;
    p[12] ^= (unchecked(p[12]) ^ unchecked(q[12])) & mask;
    p[13] ^= (unchecked(p[13]) ^ unchecked(q[13])) & mask;
    p[14] ^= (unchecked(p[14]) ^ unchecked(q[14])) & mask;
    p[15] ^= (unchecked(p[15]) ^ unchecked(q[15])) & mask;
}

function fe25519Pack(o: Uint8Array, n: Int64Array): void {
    let b: i64;
    let m = fe25519n();
    let t = fe25519n();

    fe25519Copy(t, n);
    fe25519Carry(t);
    fe25519Carry(t);
    fe25519Carry(t);
    for (let j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (let i = 1; i < 15; ++i) {
            let mp = m[i - 1];
            m[i] = t[i] - 0xffff - ((mp >> 16) & 1);
            m[i - 1] = mp & 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe25519Cmov(t, m, 1 - b);
    }
    for (let i = 0; i < 16; ++i) {
        let ti = t[i] as u32;
        o[2 * i + 0] = ti & 0xff;
        o[2 * i + 1] = ti >> 8;
    }
}

function fe25519Unpack(o: Int64Array, n: Uint8Array): void {
    let nb = n.buffer;
    for (let i = 0; i < 16; ++i) {
        o[i] = LOAD<u16, i64>(nb, i);
    }
    o[15] &= 0x7fff;
}

function fe25519Eq(a: Int64Array, b: Int64Array): bool {
    let c = new Uint8Array(32),
        d = new Uint8Array(32);

    fe25519Pack(c, a);
    fe25519Pack(d, b);

    return verify32(c, d);
}

function fe25519IsNegative(a: Int64Array): bool {
    let d = new Uint8Array(32);

    fe25519Pack(d, a);

    return (d[0] & 1) as bool;
}

function fe25519Cneg(h: Int64Array, f: Int64Array, b: bool): void {
    let negf = fe25519n();
    fe25519Sub(negf, fe25519_0, f);
    fe25519Copy(h, f);
    fe25519Cmov(h, negf, b as i64);
}

function fe25519Abs(h: Int64Array, f: Int64Array): void {
    fe25519Cneg(h, f, fe25519IsNegative(f));
}

function fe25519IsZero(a: Int64Array): bool {
    let b = new Uint8Array(32);

    fe25519Pack(b, a);
    let c: i64 = 0;
    for (let i = 0; i < 16; i++) {
        c |= b[i];
    }
    return c === 0;
}

@inline function fe25519Add(o: Int64Array, a: Int64Array, b: Int64Array): void {
    for (let i = 0; i < 16; ++i) {
        o[i] = a[i] + b[i];
    }
}

@inline function fe25519Sub(o: Int64Array, a: Int64Array, b: Int64Array): void {
    for (let i = 0; i < 16; ++i) {
        o[i] = a[i] - b[i];
    }
}

function fe25519Carry(o: Int64Array): void {
    let c: i64;

    for (let i = 0; i < 15; ++i) {
        o[i] += (1 << 16);
        c = o[i] >> 16;
        o[(i + 1)] += c - 1;
        o[i] -= c << 16;
    }
    o[15] += (1 << 16);
    c = o[15] >> 16;
    o[0] += c - 1 + 37 * (c - 1);
    o[15] -= c << 16;
}

@inline function fe25519Reduce(o: Int64Array, a: Int64Array): void {
    for (let i = 0; i < 15; ++i) {
        a[i] += 38 as i64 * a[i + 16];
    }
    fe25519Copy(o, a);
    fe25519Carry(o);
    fe25519Carry(o);
}

function fe25519Mult(o: Int64Array, a: Int64Array, b: Int64Array): void {
    let t = new Int64Array(31);

    for (let i = 0; i < 16; ++i) {
        let ai = a[i];
        for (let j = 0; j < 16; ++j) {
            t[i + j] += ai * b[j];
        }
    }
    fe25519Reduce(o, t);
}

@inline function fe25519Sq(o: Int64Array, a: Int64Array): void {
    fe25519Mult(o, a, a);
}

function fe25519Inverse(o: Int64Array, i: Int64Array): void {
    let c = fe25519n();

    fe25519Copy(c, i);
    for (let a = 253; a >= 0; --a) {
        fe25519Sq(c, c);
        if (a !== 2 && a !== 4) {
            fe25519Mult(c, c, i);
        }
    }
    fe25519Copy(o, c);
}

function fe25519Pow2523(o: Int64Array, i: Int64Array): void {
    let c = fe25519n();

    fe25519Copy(c, i);
    for (let a = 250; a >= 0; --a) {
        fe25519Sq(c, c);
        if (a !== 1) {
            fe25519Mult(c, c, i);
        }
    }
    fe25519Copy(o, c);
}

// Ed25519 group arithmetic

@inline function ge25519n(): Int64Array[] {
    return [fe25519n(), fe25519n(), fe25519n(), fe25519n()];
}

@inline function geCopy(r: Int64Array[], a: Int64Array[]): void {
    fe25519Copy(r[0], a[0]);
    fe25519Copy(r[1], a[1]);
    fe25519Copy(r[2], a[2]);
    fe25519Copy(r[3], a[3]);
}

function add(p: Int64Array[], q: Int64Array[]): void {
    let a = fe25519n(),
        b = fe25519n(),
        c = fe25519n(),
        d = fe25519n(),
        e = fe25519n(),
        f = fe25519n(),
        g = fe25519n(),
        h = fe25519n(),
        t = fe25519n();

    fe25519Sub(a, p[1], p[0]);
    fe25519Sub(t, q[1], q[0]);
    fe25519Mult(a, a, t);
    fe25519Add(b, p[0], p[1]);
    fe25519Add(t, q[0], q[1]);
    fe25519Mult(b, b, t);
    fe25519Mult(c, p[3], q[3]);
    fe25519Mult(c, c, D2);
    fe25519Mult(d, p[2], q[2]);
    fe25519Add(d, d, d);
    fe25519Sub(e, b, a);
    fe25519Sub(f, d, c);
    fe25519Add(g, d, c);
    fe25519Add(h, b, a);

    fe25519Mult(p[0], e, f);
    fe25519Mult(p[1], h, g);
    fe25519Mult(p[2], g, f);
    fe25519Mult(p[3], e, h);
}

@inline function cmov(p: Int64Array[], q: Int64Array[], b: u8): void {
    let b_ = b as i64;
    fe25519Cmov(p[0], q[0], b_);
    fe25519Cmov(p[1], q[1], b_);
    fe25519Cmov(p[2], q[2], b_);
    fe25519Cmov(p[3], q[3], b_);
}

function pack(r: Uint8Array, p: Int64Array[]): void {
    let tx = fe25519n(),
        ty = fe25519n(),
        zi = fe25519n();
    fe25519Inverse(zi, p[2]);
    fe25519Mult(tx, p[0], zi);
    fe25519Mult(ty, p[1], zi);
    fe25519Pack(r, ty);
    r[31] ^= (fe25519IsNegative(tx) as u8) << 7;
}

function scalarmult(p: Int64Array[], s: Uint8Array, q: Int64Array[]): void {
    let pc: Array<Int64Array[]> = [ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n(),
    ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n(), ge25519n()];
    let t = ge25519n(),
        b: u32;

    fe25519Copy(pc[0][0], fe25519_0);
    fe25519Copy(pc[0][1], fe25519_1);
    fe25519Copy(pc[0][2], fe25519_1);
    fe25519Copy(pc[0][3], fe25519_0);
    geCopy(pc[1], q);
    for (let i = 2; i < 16; ++i) {
        geCopy(pc[i], pc[i - 1]);
        add(pc[i], q);
    }

    geCopy(p, pc[0]);
    for (let i = 252; i >= 0; i -= 4) {
        b = (s[(i >>> 3)] >>> (i as u8 & 7)) & 0xf;
        add(p, p);
        add(p, p);
        add(p, p);
        add(p, p);
        cmov(t, unchecked(pc[15]), ((b - 16) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[14]), ((b - 15) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[13]), ((b - 14) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[12]), ((b - 13) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[11]), ((b - 12) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[10]), ((b - 11) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[9]), ((b - 10) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[8]), ((b - 9) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[7]), ((b - 8) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[6]), ((b - 7) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[5]), ((b - 6) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[4]), ((b - 5) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[3]), ((b - 4) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[2]), ((b - 3) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[1]), ((b - 2) >>> 8) as u8 & 1);
        cmov(t, unchecked(pc[0]), ((b - 1) >>> 8) as u8 & 1);
        add(p, t);
    }
}

function scalarmultBase(s: Uint8Array, p: Int64Array[]): void {
    let q = ge25519n(),
        t = ge25519n(),
        b: u8;

    fe25519Copy(p[0], fe25519_0);
    fe25519Copy(p[1], fe25519_1);
    fe25519Copy(p[2], fe25519_1);
    fe25519Copy(p[3], fe25519_0);

    fe25519Copy(q[2], fe25519_1);

    let precomp_base = precompBase();
    for (let i = 0; i <= 255; ++i) {
        b = (s[(i >>> 3)] >>> (i as u8 & 7)) & 1;
        let precomp = precomp_base[i];
        q[0] = fe25519(precomp[0]);
        q[1] = fe25519(precomp[1]);
        q[3] = fe25519(precomp[3]);
        geCopy(t, p);
        add(t, q);
        cmov(p, t, b);
    }
}

// EdDSA

function _signKeypairFromSeed(kp: Uint8Array): void {
    let pk = new Uint8Array(32);
    let d = new Uint8Array(64);
    let p = ge25519n();

    _hash(d, kp, 32);
    scClamp(d);
    scalarmultBase(d, p);
    pack(pk, p);
    for (let i = 0; i < 32; ++i) {
        kp[i + 32] = pk[i];
    }
}

function unpack(r: Int64Array[], p: Uint8Array, neg: bool = false): bool {
    let t = fe25519n(),
        chk = fe25519n(),
        num = fe25519n(),
        den = fe25519n(),
        den2 = fe25519n(),
        den4 = fe25519n(),
        den6 = fe25519n();

    fe25519Copy(r[2], fe25519_1);
    fe25519Unpack(r[1], p);
    fe25519Sq(num, r[1]);
    fe25519Mult(den, num, D);
    fe25519Sub(num, num, r[2]);
    fe25519Add(den, r[2], den);
    fe25519Sq(den2, den);
    fe25519Sq(den4, den2);
    fe25519Mult(den6, den4, den2);
    fe25519Mult(t, den6, num);
    fe25519Mult(t, t, den);
    fe25519Pow2523(t, t);
    fe25519Mult(t, t, num);
    fe25519Mult(t, t, den);
    fe25519Mult(t, t, den);
    fe25519Mult(r[0], t, den);
    fe25519Sq(chk, r[0]);
    fe25519Mult(chk, chk, den);
    if (!fe25519Eq(chk, num)) {
        fe25519Mult(r[0], r[0], SQRTM1);
    }
    fe25519Sq(chk, r[0]);
    fe25519Mult(chk, chk, den);
    if (!fe25519Eq(chk, num)) {
        return false;
    }
    if ((fe25519IsNegative(r[0]) as u8 === (p[31] >> 7)) === neg) {
        fe25519Sub(r[0], fe25519_0, r[0]);
    }
    fe25519Mult(r[3], r[0], r[1]);

    return true;
}

function isIdentity(s: Uint8Array): bool {
    return allZeros(s);
}

function isCanonical(s: Uint8Array): bool {
    if (allZeros(s)) {
        return false;
    }
    let c: u32 = (s[31] & 0x7f) ^ 0x7f;
    for (let i = 30; i > 0; --i) {
        c |= s[i] ^ 0xff;
    }
    c = (c - 1) >> 8;
    let d = ((0xed - 1) as u32 - (s[0] as u32)) >> 8;

    return !(c & d & 1);
}

function ristrettoSqrtRatioM1(x: Int64Array, u: Int64Array, v: Int64Array): bool {
    let v3 = fe25519n(), vxx = fe25519n(),
        m_root_check = fe25519n(), p_root_check = fe25519n(), f_root_check = fe25519n(),
        x_sqrtm1 = fe25519n();
    fe25519Sq(v3, v);
    fe25519Mult(v3, v3, v);
    fe25519Sq(x, v3);
    fe25519Mult(x, x, v);
    fe25519Mult(x, x, u);

    fe25519Pow2523(x, x);
    fe25519Mult(x, x, v3);
    fe25519Mult(x, x, u);

    fe25519Sq(vxx, x);
    fe25519Mult(vxx, vxx, v);
    fe25519Sub(m_root_check, vxx, u);
    fe25519Add(p_root_check, vxx, u);
    fe25519Mult(f_root_check, u, SQRTM1);
    fe25519Add(f_root_check, vxx, f_root_check);
    let has_m_root = fe25519IsZero(m_root_check);
    let has_p_root = fe25519IsZero(p_root_check);
    let has_f_root = fe25519IsZero(f_root_check);
    fe25519Mult(x_sqrtm1, x, SQRTM1);

    fe25519Cmov(x, x_sqrtm1, (has_p_root | has_f_root) as u8);
    fe25519Abs(x, x);

    return has_m_root | has_p_root;
}

function ristrettoIsCanonical(s: Uint8Array): bool {
    let c = ((s[31] & 0x7f) ^ 0x7f) as u64;
    for (let i = 30; i > 0; i--) {
        c |= s[i] ^ 0xff;
    }
    c = (c - 1) >> 8;
    let d = (0xed as u64 - 1 as u64 - (s[0] as u64)) >> 8;

    return (1 - (((c & d) | s[0]) & 1)) as bool;
}

function ristrettoUnpack(h: Int64Array[], s: Uint8Array, neg: bool = false): bool {
    let inv_sqrt = fe25519n(), s_ = fe25519n(), ss = fe25519n(),
        u1 = fe25519n(), u2 = fe25519n(), u1u1 = fe25519n(), u2u2 = fe25519n(),
        v = fe25519n(), v_u2u2 = fe25519n();

    if (!ristrettoIsCanonical(s)) {
        return false;
    }
    fe25519Unpack(s_, s);
    fe25519Sq(ss, s_);

    fe25519Copy(u1, fe25519_1);
    fe25519Sub(u1, u1, ss);
    fe25519Sq(u1u1, u1);

    fe25519Copy(u2, fe25519_1);
    fe25519Add(u2, u2, ss);
    fe25519Sq(u2u2, u2);

    fe25519Mult(v, D, u1u1);
    fe25519Sub(v, fe25519_0, v);
    fe25519Sub(v, v, u2u2);

    fe25519Mult(v_u2u2, v, u2u2);

    let was_square = ristrettoSqrtRatioM1(inv_sqrt, fe25519_1, v_u2u2);
    let x = h[0], y = h[1], z = h[2], t = h[3];

    fe25519Mult(x, inv_sqrt, u2);
    fe25519Mult(y, inv_sqrt, x);
    fe25519Mult(y, y, v);

    fe25519Mult(x, x, s_);
    fe25519Add(x, x, x);
    fe25519Abs(x, x);
    fe25519Mult(y, u1, y);

    fe25519Copy(z, fe25519_1);
    if (neg) {
        fe25519Sub(y, fe25519_0, y);
    }
    fe25519Mult(t, x, y);

    return !((!was_square) | (fe25519IsNegative(t) ^ neg) | fe25519IsZero(y));
}

function ristrettoPack(s: Uint8Array, h: Int64Array[]): void {
    let den1 = fe25519n(), den2 = fe25519n(), den_inv = fe25519n(), eden = fe25519n(),
        inv_sqrt = fe25519n(), ix = fe25519n(), iy = fe25519n(), s_ = fe25519n(),
        t_z_inv = fe25519n(), u1 = fe25519n(), u2 = fe25519n(), u1_u2u2 = fe25519n(),
        x_ = fe25519n(), y_ = fe25519n(), x_z_inv = fe25519n(), z_inv = fe25519n(),
        zmy = fe25519n();
    let x = h[0], y = h[1], z = h[2], t = h[3];

    fe25519Add(u1, z, y);
    fe25519Sub(zmy, z, y);
    fe25519Mult(u1, u1, zmy);
    fe25519Mult(u2, x, y);

    fe25519Sq(u1_u2u2, u2);
    fe25519Mult(u1_u2u2, u1, u1_u2u2);

    ristrettoSqrtRatioM1(inv_sqrt, fe25519_1, u1_u2u2);
    fe25519Mult(den1, inv_sqrt, u1);
    fe25519Mult(den2, inv_sqrt, u2);
    fe25519Mult(z_inv, den1, den2);
    fe25519Mult(z_inv, z_inv, t);

    fe25519Mult(ix, x, SQRTM1);
    fe25519Mult(iy, y, SQRTM1);
    fe25519Mult(eden, den1, INVSQRTAMD);

    fe25519Mult(t_z_inv, t, z_inv);
    let rotate = fe25519IsNegative(t_z_inv);

    fe25519Copy(x_, x);
    fe25519Copy(y_, y);
    fe25519Copy(den_inv, den2);

    fe25519Cmov(x_, iy, rotate);
    fe25519Cmov(y_, ix, rotate);
    fe25519Cmov(den_inv, eden, rotate);

    fe25519Mult(x_z_inv, x_, z_inv);
    fe25519Cneg(y_, y_, fe25519IsNegative(x_z_inv));

    fe25519Sub(s_, z, y_);
    fe25519Mult(s_, den_inv, s_);
    fe25519Abs(s_, s_);
    fe25519Pack(s, s_);
}

function ristrettoIsIdentity(s: Uint8Array): bool {
    let c = 0;

    for (let i = 0; i < 32; ++i) {
        c |= s[i];
    }
    return c === 0;
}

function ristrettoElligator(p: Int64Array[], t: Int64Array): void {
    let c = fe25519n(), n = fe25519n(), r = fe25519n(), rpd = fe25519n(),
        s = fe25519n(), s_prime = fe25519n(), ss = fe25519n(),
        u = fe25519n(), v = fe25519n(),
        w0 = fe25519n(), w1 = fe25519n(), w2 = fe25519n(), w3 = fe25519n();

    fe25519Sq(r, t);
    fe25519Mult(r, SQRTM1, r);
    fe25519Add(u, r, fe25519_1);
    fe25519Mult(u, u, ONEMSQD);
    fe25519Sub(c, fe25519_0, fe25519_1);
    fe25519Add(rpd, r, D);
    fe25519Mult(v, r, D);
    fe25519Sub(v, c, v);
    fe25519Mult(v, v, rpd);

    let wasnt_square = 1 - (ristrettoSqrtRatioM1(s, u, v) as u8);
    fe25519Mult(s_prime, s, t);
    fe25519Abs(s_prime, s_prime);
    fe25519Sub(s_prime, fe25519_0, s_prime);
    fe25519Cmov(s, s_prime, wasnt_square);
    fe25519Cmov(c, r, wasnt_square);

    fe25519Sub(n, r, fe25519_1);
    fe25519Mult(n, n, c);
    fe25519Mult(n, n, SQDMONE);
    fe25519Sub(n, n, v);

    fe25519Add(w0, s, s);
    fe25519Mult(w0, w0, v);
    fe25519Mult(w1, n, SQRTADM1);
    fe25519Sq(ss, s);
    fe25519Sub(w2, fe25519_1, ss);
    fe25519Add(w3, fe25519_1, ss);

    fe25519Mult(p[0], w0, w3);
    fe25519Mult(p[1], w2, w1);
    fe25519Mult(p[2], w1, w3);
    fe25519Mult(p[3], w0, w2);
}

function ristrettoFromUniform(s: Uint8Array, r: Uint8Array): void {
    let r0 = fe25519n(), r1 = fe25519n();
    let p0 = ge25519n(), p1 = ge25519n();

    fe25519Unpack(r0, r.subarray(0, 32));
    fe25519Unpack(r1, r.subarray(32, 64));
    ristrettoElligator(p0, r0);
    ristrettoElligator(p1, r1);
    add(p0, p1);
    ristrettoPack(s, p0);
}

// Ed25519

let B = new Uint8Array(32);
for (let i = 0; i < 32; ++i) {
    B[i] = 0x66;
}

function _signSyntheticRHv(hs: Uint8Array, r: isize, Z: Uint8Array, sk: Uint8Array): isize {
    let zeros = new Uint8Array(128);
    let empty_labelset = new Uint8Array(3);
    let Zlen = Z.length;

    if (Zlen > 128 - (32 + 3)) {
        Z = hash(Z);
        Zlen = Z.length;
    }
    empty_labelset[0] = 0x02;

    r = _hashUpdate(hs, B, 32, r);
    r = _hashUpdate(hs, empty_labelset, 3, r);
    r = _hashUpdate(hs, Z, Zlen, r);
    r = _hashUpdate(hs, zeros, 128 - ((32 + 3 + Zlen) & 127), r);
    r = _hashUpdate(hs, sk, 32, r);
    r = _hashUpdate(hs, zeros, 128 - (32 & 127), r);
    r = _hashUpdate(hs, empty_labelset, 3, r);
    r = _hashUpdate(hs, sk.subarray(32), 32, r);

    return r;
}

function _signDetached(sig: Uint8Array, m: Uint8Array, kp: Uint8Array, Z: Uint8Array): void {
    let R = ge25519n();
    let az = new Uint8Array(64);
    let nonce = new Uint8Array(64);
    let hram = new Uint8Array(64);
    let x = new Int64Array(64);
    let mlen = m.length;
    let hs = _hashInit();
    let r: isize = 0;

    _hash(az, kp, 32);
    if (Z.length > 0) {
        r = _signSyntheticRHv(hs, r, Z, az);
    } else {
        r = _hashUpdate(hs, az.subarray(32), 32, r);
    }
    r = _hashUpdate(hs, m, mlen, r);
    _hashFinal(hs, nonce, 32 + mlen, r);
    setU8(sig, kp.subarray(32), 32);

    scReduce(nonce);
    scalarmultBase(nonce, R);
    pack(sig, R);

    hs = _hashInit();
    r = _hashUpdate(hs, sig, 64, 0);
    r = _hashUpdate(hs, m, mlen, r);
    _hashFinal(hs, hram, 64 + mlen, r);
    scReduce(hram);
    scClamp(az);
    for (let i = 0; i < 32; ++i) {
        x[i] = nonce[i];
    }
    for (let i = 0; i < 32; ++i) {
        for (let j = 0; j < 32; ++j) {
            x[i + j] += (hram[i] as i64) * (az[j] as i64);
        }
    }
    scModL(sig.subarray(32), x);
}

function _signVerifyDetached(sig: Uint8Array, m: Uint8Array, pk: Uint8Array): bool {
    if (!isCanonical(pk) || isIdentity(pk) || !isCanonical(sig.subarray(32))) {
        return false;
    }
    let A = ge25519n();
    if (!unpack(A, pk, true)) {
        return false;
    }
    let h = new Uint8Array(64);
    let hs = _hashInit();
    let r = _hashUpdate(hs, sig, 32, 0);
    r = _hashUpdate(hs, pk, 32, r);
    r = _hashUpdate(hs, m, m.length, r);
    _hashFinal(hs, h, 32 + 32 + m.length, r);
    scReduce(h);

    let R = ge25519n();
    let rcheck = new Uint8Array(32);
    scalarmult(R, h, A);
    scalarmultBase(sig.subarray(32), A);
    add(R, A);
    pack(rcheck, R);

    return verify32(rcheck, sig.subarray(0, 32));
}

// Exported API

/**
 * Signature size, in bytes
 */
@global export const SIGN_BYTES: isize = 64;

/**
 * Public key size, in bytes
 */
@global export const SIGN_PUBLICKEYBYTES: isize = 32;

/**
 * Secret key size, in bytes
 */
@global export const SIGN_SECRETKEYBYTES: isize = 32;

/**
 * Key pair size, in bytes
 */
@global export const SIGN_KEYPAIRBYTES: isize = 64;

/**
 * Seed size, in bytes
 */
@global export const SIGN_SEEDBYTES: isize = 32;

/**
 * Recommended random bytes size, in bytes
 */
@global export const SIGN_RANDBYTES: isize = 32;

/**
 * Hash function output size, in bytes
 */
@global export const HASH_BYTES: isize = 64;

/**
 * HMAC output size, in bytes
 */
@global export const HMAC_BYTES: isize = 64;

/**
 * Size of an encoded scalar, in bytes
 */
@global export const FA_SCALARBYTES: isize = 32;

/**
 * Size of an encoded point, in bytes
 */
@global export const FA_POINTBYTES: isize = 32;

/**
 * Fill an array with zeros
 * @param x Array to clear
 */
@global export function memzero(x: Uint8Array): void {
    for (let i = 0, j = x.length; i < j; ++i) {
        x[i] = 0;
    }
}

/**
 * Check two arrays for equality
 * @param x First array
 * @param y Second array
 * @returns true if `x === y`
 */
@global export function equals(x: Uint8Array, y: Uint8Array): bool {
    let len = x.length;
    let d: u8 = 0;

    if (len === 0 || len !== y.length) {
        return false;
    }
    for (let i = 0; i < len; ++i) {
        d |= x[i] ^ y[i];
    }
    return d === 0;
}

/**
 * Sign a message and returns its signature.
 * @param m Message to sign
 * @param kp Key pair (`SIGN_KEYPAIRBYTES` long)
 * @param Z Random bytes. This can be an empty array to produce deterministic
 *     signatures
 * @returns Signature
 */
@global export function sign(m: Uint8Array, kp: Uint8Array, Z: Uint8Array): Uint8Array {
    let sig = new Uint8Array(SIGN_BYTES);
    _signDetached(sig, m, kp, Z);

    return sig;
}

/**
 * Verify a signature
 * @param m Message
 * @param sig Signature
 * @param pk Public key
 * @returns `true` on success
 */
@global export function signVerify(sig: Uint8Array, m: Uint8Array, pk: Uint8Array): bool {
    if (sig.length !== SIGN_BYTES) {
        throw new Error('bad signature size');
    }
    if (pk.length !== SIGN_PUBLICKEYBYTES) {
        throw new Error('bad public key size');
    }
    return _signVerifyDetached(sig, m, pk);
}

/**
 * Create a new key pair from a seed
 * @param seed Seed (`SIGN_SEEDBYTES` long)
 * @returns Key pair
 */
@global export function signKeypairFromSeed(seed: Uint8Array): Uint8Array {
    if (seed.length !== SIGN_SEEDBYTES) {
        throw new Error('bad seed size');
    }
    let kp = new Uint8Array(SIGN_KEYPAIRBYTES);
    for (let i = 0; i < 32; ++i) {
        kp[i] = seed[i];
    }
    _signKeypairFromSeed(kp);

    return kp;
}

/**
 * Return the public key from a key pair
 * @param kp Key pair
 * @returns Public key
 */
@global export function signPublicKey(kp: Uint8Array): Uint8Array {
    const len = SIGN_PUBLICKEYBYTES;
    let pk = new Uint8Array(len);

    for (let i = 0; i < len; ++i) {
        pk[i] = kp[i + 32];
    }
    return pk;
}

/**
 * Return the secret key from a key pair
 * @param kp Key pair
 * @returns Secret key
 */
@global export function signSecretKey(kp: Uint8Array): Uint8Array {
    const len = SIGN_SECRETKEYBYTES;
    let sk = new Uint8Array(len);

    for (let i = 0; i < len; ++i) {
        sk[i] = kp[i];
    }
    return sk;
}

/**
 * Initialize a multipart hash computation
 * @returns A hash function state
 */
@global export function hashInit(): Uint8Array {
    return _hashInit();
}

/**
 * Absorb data to be hashed
 * @param st Hash function state
 * @param m (partial) message
 */
@global export function hashUpdate(st: Uint8Array, m: Uint8Array): void {
    let r = load64(st, 64 + 128);
    let t = load64(st, 64 + 128 + 8);
    let n = m.length;

    t += n;
    r = _hashUpdate(st, m, n, r as isize);
    store64(st, 64 + 128, r as u64);
    store64(st, 64 + 128 + 8, t as u64);
}

/**
 * Finalize a hash computation
 * @param st Hash function state
 * @returns Hash
 */
@global export function hashFinal(st: Uint8Array): Uint8Array {
    let h = new Uint8Array(HASH_BYTES);
    let r = load64(st, 64 + 128);
    let t = load64(st, 64 + 128 + 8);

    _hashFinal(st, h, t as isize, r as isize);

    return h;
}

/**
 * Compute a hash for a single-part message
 * @param m Message
 * @returns Hash
 */
@global export function hash(m: Uint8Array): Uint8Array {
    let st = hashInit();

    hashUpdate(st, m);

    return hashFinal(st);
}

/**
 * HMAC-SHA-512
 * @param m Message
 * @param k Key
 * @returns `HMAC-SHA-512(m, k)`
 */
@global export function hmac(m: Uint8Array, k: Uint8Array): Uint8Array {
    return _hmac(m, k);
}

/**
 * Compute the multiplicative inverse of a scalar
 * @param s Scalar
 * @returns `s^-1`
 */
@global export function faScalarInverse(s: Uint8Array): Uint8Array {
    return scInverse(s);
}

/**
 * Compute s mod the order of the prime order group
 *
 * @param s Scalar (between 32 and 64 bytes)
 * @returns `s` reduced mod `L`
 */
@global export function faScalarReduce(s: Uint8Array): Uint8Array {
    let s_ = new Uint8Array(64);
    if (s_.length < 32 || s_.length > 64) {
        throw new Error('faScalarReduce() argument should be between 32 and 64 bytes long');
    }
    setU8(s_, s);
    scReduce(s_);
    let r = new Uint8Array(32);
    for (let i = 0; i < 32; ++i) {
        r[i] = s_[i];
    }
    return r;
}

/**
 * Multiply `s` by the group cofactor
 *
 * @param s Scalar (32 bytes)
 * @returns `s * 8`
 */
@global export function faScalarCofactorMult(s: Uint8Array): Uint8Array {
    if (s.length !== 32) {
        throw new Error('faScalarCofactorMult() argument should be 32 bytes long');
    }
    if ((s[31] & 224) !== 0) {
        throw new Error("faScalarCofactorMult() would overflow");
    }
    let r = new Uint8Array(32), t: u8 = 0;
    for (let i = 0; i < 32; i++) {
        let si = s[i];
        r[i] = (si << 3) | t;
        t = (si >>> 5);
    }
    return r;
}

/**
 * Compute the additive inverse of a scalar (mod L)
 * @param s Scalar
 * @returns `-s`
 */
@global export function faScalarNegate(s: Uint8Array): Uint8Array {
    let t = new Uint8Array(32), t_ = new Uint8Array(64), s_ = new Uint8Array(64);
    for (let i = 0; i < 32; i++) {
        t_[32 + i] = _L[i] as u8;
    }
    setU8(s_, s);
    scSub(t_, s_);
    scReduce(t_);
    setU8(t, t_.subarray(0, 32));

    return t;
}

/**
 * Compute the complement of a scalar (mod L)
 * @param s Scalar
 * @returns `1-s`
 */
@global export function faScalarComplement(s: Uint8Array): Uint8Array {
    let t = new Uint8Array(32), t_ = new Uint8Array(64), s_ = new Uint8Array(64);
    t_[0] = 1;
    for (let i = 0; i < 32; i++) {
        t_[32 + i] = _L[i] as u8;
    }
    setU8(s_, s);
    scSub(t_, s_);
    scReduce(t_);
    setU8(t, t_.subarray(0, 32));

    return t;
}

/**
 * Compute `x + y (mod L)`
 * @param x Scalar
 * @param y Scalar
 * @returns `x + y (mod L)`
 */
@global export function faScalarAdd(x: Uint8Array, y: Uint8Array): Uint8Array {
    let x_ = new Uint8Array(64), y_ = new Uint8Array(64);
    setU8(x_, x);
    setU8(y_, y);
    scAdd(x_, y_);

    return faScalarReduce(x_);
}

/**
 * Compute `x - y (mod L)`
 * @param x Scalar
 * @param y Scalar
 * @returns `x - y (mod L)`
 */
@global export function faScalarSub(x: Uint8Array, y: Uint8Array): Uint8Array {
    let yn = faScalarNegate(y);

    return faScalarAdd(x, yn);
}

/**
 * Compute `x * y (mod L)`
 * @param x Scalar
 * @param y Scalar
 * @returns `x * y (mod L)`
 */
@global export function faScalarMult(x: Uint8Array, y: Uint8Array): Uint8Array {
    let x_ = new Int64Array(64), y_ = new Int64Array(64);
    let o = new Int64Array(64), o_ = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        x_[i] = x[i] as i64;
    }
    for (let i = 0; i < 32; i++) {
        y_[i] = y[i] as i64;
    }
    scMult(o, x_, y_);
    for (let i = 0; i < 32; i++) {
        o_[i] = o[i] as u8;
    }
    return o_;
}

/**
 * Multiply a point `q` by a scalar `s`
 * @param q Compressed EC point
 * @param s Scalar
 * @returns Compressed EC point `q * s`
 */
@global export function faEdPointMult(s: Uint8Array, q: Uint8Array): Uint8Array {
    let p_ = ge25519n();
    let q_ = ge25519n();
    if (!unpack(q_, q, false) || !faEdPointValidate(q)) {
        return null;
    }
    scalarmult(p_, s, q_);
    let p = new Uint8Array(32);
    pack(p, p_);
    if (isIdentity(p)) {
        return null;
    }
    return p;
}

/**
 * Multiply the base point by a scalar `s`
 * @param s Scalar
 * @returns Compressed EC point `B * s`
 */
@global export function faEdBasePointMult(s: Uint8Array): Uint8Array {
    if (allZeros(s)) {
        return null;
    }
    let p = new Uint8Array(32);
    let p_ = ge25519n();
    scalarmultBase(s, p_);
    pack(p, p_);

    return p;
}

/**
 * Multiply a point `q` by a scalar `s` after clamping `s`
 * @param q Compressed EC point
 * @param s Scalar
 * @returns Compressed EC point `q * clamp(s)`
 */
@global export function faEdPointMultClamp(s: Uint8Array, q: Uint8Array): Uint8Array {
    let s_ = new Uint8Array(32);
    setU8(s_, s);
    scClamp(s_);

    return faEdPointMult(s, q);
}

/**
 * Multiply the base point by a clamped scalar `s`
 * @param s Scalar
 * @returns Compressed EC point `B * clamp(s)`
 */
@global export function faEdBasePointMultClamp(s: Uint8Array): Uint8Array {
    let s_ = new Uint8Array(32);
    setU8(s_, s);
    scClamp(s_);

    return faEdBasePointMult(s);
}

/**
 * Verify that the point is on the main subgroup
 * @param q Compressed EC point
 * @returns `true` if verification succeeds
 */
@global export function faEdPointValidate(q: Uint8Array): bool {
    let l = new Uint8Array(32);
    let p_ = ge25519n();
    let q_ = ge25519n();

    for (let i = 0; i < 32; ++i) {
        l[i] = _L[i] as u8;
    }
    if (!unpack(q_, q, false)) {
        return false;
    }
    scalarmult(p_, l, q_);

    let c: i64 = 0;
    let x = p_[0];
    for (let i = 0; i < 16; ++i) {
        c |= x[i];
    }
    return c === 0;
}

/**
 * Point addition
 * @param p Compressed EC point
 * @param q Compressed EC point
 * @returns `p` + `q`
 */
@global export function faEdPointAdd(p: Uint8Array, q: Uint8Array): Uint8Array {
    let o = new Uint8Array(32);
    let p_ = ge25519n();
    let q_ = ge25519n();
    if (!unpack(p_, p, false) || !unpack(q_, q, false)) {
        return null;
    }
    add(p_, q_);
    pack(o, p_);

    return o;
}

/**
 * Point substraction
 * @param p Compressed EC point
 * @param q Compressed EC point
 * @returns `p` - `q`
 */
@global export function faEdPointSub(p: Uint8Array, q: Uint8Array): Uint8Array {
    let o = new Uint8Array(32);
    let p_ = ge25519n();
    let q_ = ge25519n();
    if (!unpack(p_, p, false) || !unpack(q_, q, true)) {
        return null;
    }
    add(p_, q_);
    pack(o, p_);

    return o;
}

/**
 * Multiply a point `q` by a scalar `s`
 * @param q Ristretto-compressed EC point
 * @param s Scalar
 * @returns Compressed EC point `q * s`
 */
@global export function faPointMult(s: Uint8Array, q: Uint8Array): Uint8Array {
    let p_ = ge25519n();
    let q_ = ge25519n();
    if (!ristrettoUnpack(q_, q)) {
        return null;
    }
    scalarmult(p_, s, q_);
    let p = new Uint8Array(32);
    ristrettoPack(p, p_);
    if (ristrettoIsIdentity(p)) {
        return null;
    }
    return p;
}

/**
 * Multiply the base point by a scalar `s`
 * @param s Scalar
 * @returns Ristretto-compressed EC point `B * s`
 */
@global export function faBasePointMult(s: Uint8Array): Uint8Array {
    if (allZeros(s)) {
        return null;
    }
    let p = new Uint8Array(32);
    let p_ = ge25519n();
    scalarmultBase(s, p_);
    ristrettoPack(p, p_);

    return p;
}

/**
 * Verify that the point is on the main subgroup
 * @param q Ristretto-compressed EC point
 * @returns `true` if verification succeeds
 */
@global export function faPointValidate(q: Uint8Array): bool {
    let q_ = ge25519n();
    return (!allZeros(q)) & ristrettoUnpack(q_, q);
}

/**
 * Point addition
 * @param p Risterto-compressed EC point
 * @param q Risterto-compressed EC point
 * @returns `p` + `q`
 */
@global export function faPointAdd(p: Uint8Array, q: Uint8Array): Uint8Array {
    let o = new Uint8Array(32);
    let p_ = ge25519n();
    let q_ = ge25519n();
    if (!ristrettoUnpack(p_, p) || !ristrettoUnpack(q_, q, false)) {
        return null;
    }
    add(p_, q_);
    ristrettoPack(o, p_);

    return o;
}

/**
 * Point substraction
 * @param p Ristretto-compressed EC point
 * @param q Ristretto-compressed EC point
 * @returns `p` - `q`
 */
@global export function faPointSub(p: Uint8Array, q: Uint8Array): Uint8Array {
    let o = new Uint8Array(32);
    let p_ = ge25519n();
    let q_ = ge25519n();
    if (!ristrettoUnpack(p_, p) || !ristrettoUnpack(q_, q, true)) {
        return null;
    }
    add(p_, q_);
    ristrettoPack(o, p_);

    return o;
}

/**
 * Hash-to-point
 * @param r 512 bit hash
 * @returns Ristretto-compressed EC point
 */
@global export function faPointFromUniform(r: Uint8Array): Uint8Array {
    let p = new Uint8Array(32);

    ristrettoFromUniform(p, r);

    return p;
}
