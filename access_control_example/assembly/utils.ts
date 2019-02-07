import { rng_next_u64, KVStore, bytes_to_string, Response } from "./http_guest";

/**
 * Copy a typed array slice
 * @param dst destination
 * @param src source
 * @param offset destination offset (optional)
 */
export function u8ArrayCopy(dst: Uint8Array, src: Uint8Array, offset: isize = 0): void {
    let len = src.length;
    for (let i = 0; i < len; i++) {
        dst[offset + i] = src[i];
    }
}

/**
 * Convert a generic array to a typed array
 * @param g generic array
 * @returns typed array
 */
export function genericArrayToU8Array(g: Array<u8>): Uint8Array {
    let len = g.length;
    let ret = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        ret[i] = g[i];
    }
    return ret;
}

/**
 * Converts a typed array to a generic array
 * @param a typed array
 * @returns generic array
 */
export function u8ArrayToGenericArray(a: Uint8Array): Array<u8> {
    let len = a.length;
    let ret = new Array<u8>();
    for (let i = 0; i < len; i++) {
        ret.push(a[i]);
    }
    return ret;
}

/**
 * Decode a length-prefixed byte sequence
 * @param bytes byte sequence
 * @returns decoded sequence
 */
export function bytesDecode(bytes: Uint8Array): Uint8Array {
    let remaining = bytes.length;
    if (remaining < 2) {
        throw "invalid length";
    }
    let blen = (bytes[0] | (bytes[1] << 8)) as i32;
    if (remaining - 2 < blen) {
        throw "inconsistent length";
    }
    return bytes.subarray(2, 2 + blen);
}

/**
 * Encode a byte sequence to add a length prefix
 * @param bytes byte sequence
 * @returns length-prefixed byte sequence
 */
export function bytesEncode(bytes: Uint8Array): Uint8Array {
    let len = bytes.length;
    let ret = new Uint8Array(2 + len);
    ret[0] = len as u8;
    ret[1] = ((len >>> 8) & 0xff) as u8;
    for (let i = 0; i < len; i++) {
        ret[2 + i] = bytes[i];
    }
    return ret;
}

/**
 * Encode a string as a length-prefixed byte sequence
 * @param str string
 * @returns length-prefixed string
 */
export function strEncode(str: string): Uint8Array {
    let bytes_pnt = str.toUTF8();
    let bytes_len = str.lengthUTF8 - 1;
    let bytes = new Uint8Array(bytes_len);
    for (let i = 0; i < bytes_len; i++) {
        bytes[i] = load<u8>(bytes_pnt + i);
    }
    return bytesEncode(bytes);
}

/**
 * Return the next byte sequence as a subarray
 * @param bytes encoded sequence
 * @returns subarray
 */
export function bytesNext(bytes: Uint8Array): Uint8Array {
    let blen = (bytes[0] | (bytes[1] << 8)) as i32;
    return bytes.subarray(2 + blen);
}

/**
 * Fill an array with random bits
 * @param v array
 */
export function getRandom(v: Uint8Array): void {
    let len = v.length;
    for (let i = 0; i < len; i++) {
        v[i] = rng_next_u64() as u8;
    }
}

let kvs: KVStore = null;

/**
 * Initialize the KV store wrappers
 * @param _kvs KVStore object
 */
export function kvsInit(_kvs: KVStore): void {
    kvs = _kvs;
}

/**
 * Return a key for type `a` and name `b`
 * @param a key type
 * @param b key name
 * @returns key
 */
export function keyFor(context: string, b: Uint8Array): string {
    if (!isUtf8(b)) {
        throw "Key must be a valid UTF-8 string";
    }
    let b_str = bytes_to_string(u8ArrayToGenericArray(b));

    return context + "|" + b_str;
}

/**
 * Get a key from the KV store
 * @param key key
 * @returns value or null
 */
export function kvsGet(key: string): Uint8Array {
    let value = kvs.get(key);
    if (value === null) {
        return null;
    }
    return genericArrayToU8Array(value);
}

/**
 * Insert a value in the KV store
 * @param key key
 * @param value value
 * @returns inserted (`true`) or replaced (`false`)
 */
export function kvsInsert(key: string, value: Uint8Array): bool {
    return kvs.insert(key, u8ArrayToGenericArray(value));
}

/**
 * Insert a value in the KV store if the key doesn't exist already
 * @param key key
 * @param value value
 * @returns inserted (`true`) or ignored (`false`)
 */
export function kvsUpsert(key: string, value: Uint8Array): bool {
    return kvs.upsert(key, u8ArrayToGenericArray(value));
}

/**
 * Remove a value from the KV store
 * @param key key
 */
export function kvsDelete(key: string): bool {
    return kvs.remove(key)
}

/**
 * Load a 64 bit value
 * @param x typed array
 * @param offset offset
 * @returns value
 */
export function load64(x: Uint8Array, offset: isize): u64 {
    let u: u64 = 0;
    for (let i = 0; i < 8; ++i) {
        u = (u << 8) | x[offset + i];
    }
    return u;
}

/**
 * Store a 64 bit value
 * @param x array
 * @param offset offset
 * @param u value
 */
export function store64(x: Uint8Array, offset: isize, u: u64): void {
    for (let i = 7; i >= 0; --i) {
        x[offset + i] = u as u8;
        u >>= 8;
    }
}

/**
 * Check that an array contains only valid UTF-8 sequences
 * @param s array
 * @returns `true` on success
 */
export function isUtf8(s: Uint8Array): bool {
    var len = s.length;
    for (let i = 0; i < len;) {
        let c = s[i++];
        if (c < 0x80) {
            continue;
        }
        if (c < 0xc0 || (s[i++] & 0xc0) !== 0x80) {
            return false;
        }
        if (c < 0xe0) {
            continue;
        }
        if ((s[i++] & 0xc0) !== 0x80) {
            return false;
        }
        if (c < 0xf0) {
            continue;
        }
        if (c >= 0xf8 || (s[i++] & 0xc0) !== 0x80) {
            return false;
        }
    }
    return true;
}

/**
 * Return a `Response` object with headers to prevent caching
 * @returns a `Response` object
 */
export function uncachedResponse(): Response {
    let response = new Response();
    response.set_header("Cache-Control", ["private, no-cache, no-store, must-revalidate, max-age=0"]);

    return response;
}
