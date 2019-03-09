import { run_user_kvs, Request, KVStore, Response, Time } from "./http_guest";
import {
    hmac, faScalarReduce, faPointMult, SIGN_BYTES, SIGN_PUBLICKEYBYTES, signVerify,
    faPointValidate, FA_SCALARBYTES, FA_POINTBYTES
} from "./crypto";
import {
    bytesDecode, bytesEncode, bytesNext, genericArrayToU8Array, getRandom, keyFor,
    kvsGet, kvsInit, kvsInsert, kvsUpsert, strEncode, u8ArrayCopy, u8ArrayToGenericArray,
    load64, store64, isUtf8, uncachedResponse, kvsDelete
} from "./utils";

/**
 * Unique name for the application. It doesn't have to be an actual host name.
 */
const DOMAIN = "example.wasm.fastly-terrarium.com";

/**
 * Maximum user name length
 */
const MAX_USERNAME_LENGTH = 100;

/*
 * Maximum body length
 */
const MAX_BODY_LENGTH = 1000;

/**
 * A pseudo-random secrer scalar is returned for nonexistent users.
 * Since it should be deterministic, a key is created and
 * persisted, if necessary.
 */
function getHashkey(): Uint8Array {
    let key = kvsGet("hash_key");
    if (!key) {
        key = new Uint8Array(32);
        getRandom(key);
        kvsInsert("hash_key", key);
    }
    return key;
}

/**
 * login-get-blind-salt-and-nonce API
 *
 * Return a blind salt for a (user name, blind auth info),
 * as well as a random nonce.
 *
 * If the user doesn't exist, we still return a tuple, but with
 * a blind salt derived from the user name and the hmac key.
 *
 * Note that access to the KV store is not constant-time,
 * so totally eliminating user enumeration is a non-goal.
 *
 * In: username || blind_auth_info
 * Out: salt || nonce
 *
 * @param req HTTP Request
 */
function loginGetBlindSaltAndNonce(req: Request): Response {
    let response = uncachedResponse();
    response.status = 400;

    let body = genericArrayToU8Array(req.body);
    let username = bytesDecode(body);
    if (!username) {
        response.body_string = "Empty username";
        return response;
    }
    let blind_auth_info_ = bytesNext(body);
    if (blind_auth_info_.length !== FA_POINTBYTES) {
        response.body_string = "Invalid blind auth info (length)";
        return response;
    }
    let blind_auth_info = new Uint8Array(FA_POINTBYTES);
    u8ArrayCopy(blind_auth_info, blind_auth_info_);

    let now = Time.now().seconds as u64;
    let blind_salt_and_nonce = new Uint8Array(FA_POINTBYTES + 32);
    let nonce = blind_salt_and_nonce.subarray(FA_POINTBYTES);
    getRandom(nonce);

    let nonce_and_ts_key = keyFor("session_nonce_and_ts", username);
    let nonce_and_ts = kvsGet(nonce_and_ts_key);
    if (nonce_and_ts) {
        let ts = load64(nonce_and_ts, 32);
        if (ts > now || now - ts > 3) {
            nonce_and_ts = null;
        }
    }
    if (nonce_and_ts) {
        u8ArrayCopy(nonce, nonce_and_ts.subarray(0, 32));
    } else {
        nonce_and_ts = new Uint8Array(32 + 8);
        u8ArrayCopy(nonce_and_ts, nonce);
        store64(nonce_and_ts, 32, now);
    }
    kvsInsert(nonce_and_ts_key, nonce_and_ts);

    let hash_key = getHashkey();
    let r = hmac(username, hash_key).subarray(0, FA_POINTBYTES);
    let r_and_pk_key = keyFor("user_r_and_pk", username);
    let r_and_pk = kvsGet(r_and_pk_key);
    if (r_and_pk) {
        r = r_and_pk.subarray(0, FA_POINTBYTES);
    }
    let blind_salt = faPointMult(r, blind_auth_info);
    if (blind_salt === null) {
        response.body_string = "Invalid auth info (identity)";
        return response;
    }
    u8ArrayCopy(blind_salt_and_nonce, blind_salt);

    response.body = u8ArrayToGenericArray(blind_salt_and_nonce);
    response.status = 200;

    return response;
}

/**
 * login API
 *
 * Check that the client sent a valid signature for
 * c = (domain || username || nonce) using the stored public key for that user,
 * and onsider it authenticated if verification succeeds.
 *
 * IN: username || S(pk, c)
 * OUT: HTTP status code
 *
 * @param req HTTP Request
 */
function login(req: Request): Response {
    let response = uncachedResponse();
    response.status = 400;

    let body = genericArrayToU8Array(req.body);
    let username = bytesDecode(body);
    if (!username) {
        return response;
    }
    let signature_ = bytesNext(body);
    if (signature_.length !== SIGN_BYTES) {
        response.body_string = "Invalid signature (length)";
        return response;
    }
    let signature = new Uint8Array(SIGN_BYTES);
    u8ArrayCopy(signature, signature_);

    let nonce_and_ts_key = keyFor("session_nonce_and_ts", username);
    let nonce_and_ts = kvsGet(nonce_and_ts_key);
    if (!nonce_and_ts) {
        response.body_string = "Missing nonce";
        return response;
    }
    let nonce = nonce_and_ts.subarray(0, 32);

    let r_and_pk_key = keyFor("user_r_and_pk", username);
    let r_and_pk = kvsGet(r_and_pk_key);
    if (!r_and_pk) {
        response.body_string = "Incorrect (login, password) pair";
        response.status = 401;
        return response;
    }
    let pk = new Uint8Array(SIGN_PUBLICKEYBYTES);
    u8ArrayCopy(pk, r_and_pk.subarray(FA_SCALARBYTES, FA_SCALARBYTES + SIGN_PUBLICKEYBYTES));

    let domain_bin = strEncode(DOMAIN);
    let username_bin = bytesEncode(username);
    let challenge = new Uint8Array(domain_bin.length + username_bin.length + nonce.length);
    u8ArrayCopy(challenge, domain_bin);
    u8ArrayCopy(challenge, username_bin, domain_bin.length);
    u8ArrayCopy(challenge, nonce, domain_bin.length + username_bin.length);

    let verified = signVerify(signature, challenge, pk);
    if (!verified) {
        response.body_string = "Incorrect (login, password) pair";
        response.status = 401;
        return response;
    }
    response.body_string = "Access allowed";
    response.status = 200;

    return response;
}

/**
 * /signup-get-blind-salt API
 *
 * Returns a blind salt for the given user, creating a secret if needed.
 *
 * IN: username || blind_auth_info
 * OUT: blind_salt
 *
 * @param req HTTP Requset
 */
function signupGetBlindSalt(req: Request): Response {
    let response = uncachedResponse();
    response.status = 400;

    let body = genericArrayToU8Array(req.body);
    let username = bytesDecode(body);
    if (!username || username.length >= MAX_USERNAME_LENGTH || !isUtf8(username)) {
        response.body_string = "Invalid username";
        return response;
    }
    let blind_auth_info_ = bytesNext(body);
    if (blind_auth_info_.length !== FA_POINTBYTES) {
        response.body_string = "Invalid auth info (length)";
        return response;
    }
    let blind_auth_info = new Uint8Array(FA_POINTBYTES);
    u8ArrayCopy(blind_auth_info, blind_auth_info_);
    if (!faPointValidate(blind_auth_info)) {
        response.body_string = "Invalid auth info (point encoding)";
        return response;
    }
    let r_and_pk_key = keyFor("user_r_and_pk", username);
    if (kvsGet(r_and_pk_key)) {
        response.body_string = "An account with that name already exists";
        response.status = 403;
        return response;
    }
    let signup_r_key = keyFor("user_signup_r", username);
    let r = kvsGet(signup_r_key);
    if (!r) {
        let r_ = new Uint8Array(64);
        getRandom(r_);
        r = faScalarReduce(r_);
        if (!kvsUpsert(signup_r_key, r)) {
            r = kvsGet(signup_r_key) || r;
        }
    }
    let blind_salt = faPointMult(r, blind_auth_info);
    if (blind_salt === null) {
        response.body_string = "Invalid auth info (identity)";
        return response;
    }
    response.body = u8ArrayToGenericArray(blind_salt);
    response.status = 200;

    return response;
}

/**
 * /signup API
 *
 * Register a new user by storing the secret scalar r
 * and the user's public key in the database.
 *
 * IN: username || pk
 * OUT: HTTP status code
 *
 * @param req HTTP Request
 */
function signup(req: Request): Response {
    let response = uncachedResponse();
    response.status = 400;

    let body = genericArrayToU8Array(req.body);
    let username = bytesDecode(body);
    if (!username || username.length >= MAX_USERNAME_LENGTH || !isUtf8(username)) {
        response.body_string = "Invalid username";
        return response;
    }
    let pk_ = bytesNext(body);
    if (pk_.length != SIGN_PUBLICKEYBYTES) {
        response.body_string = "Invalid public key (length)";
        return response;
    }
    let pk = new Uint8Array(SIGN_PUBLICKEYBYTES);
    u8ArrayCopy(pk, pk_);
    if (!faPointValidate(pk)) {
        response.body_string = "Invalid public key (encoded point)";
        return response;
    }
    let signup_r_key = keyFor("user_signup_r", username);
    let r = kvsGet(signup_r_key);
    if (!r) {
        response.body_string = "Timeout";
        return response;
    }
    let r_and_pk_key = keyFor("user_r_and_pk", username);
    let r_and_pk = new Uint8Array(FA_SCALARBYTES + SIGN_PUBLICKEYBYTES);
    u8ArrayCopy(r_and_pk, r);
    u8ArrayCopy(r_and_pk, pk, r.length);
    if (kvsUpsert(r_and_pk_key, r_and_pk) == false) {
        response.body_string = "An account with that name already exists";
        response.status = 403;
        return response;
    }
    kvsDelete(signup_r_key);
    response.status = 200;

    return response;
}

/**
 * Entry point callback
 *
 * @param _kvs KVStore object
 * @param req HTTP request
 */
function userEntryPoint(_kvs: KVStore, req: Request): Response {
    kvsInit(_kvs);
    let url = req.url;
    let method = req.method;
    if (method == "POST") {
        if (req.body.length >= MAX_BODY_LENGTH) {
            let response = uncachedResponse();
            response.status = 413;
            response.body_string = "Request too large";
            return response;
        }
        if (url == "/login-get-blind-salt-and-nonce") {
            return loginGetBlindSaltAndNonce(req);
        } else if (url == "/login") {
            return login(req);
        } else if (url == "/signup-get-blind-salt") {
            return signupGetBlindSalt(req);
        } else if (url == "/signup") {
            return signup(req);
        }
    }
    let response = uncachedResponse();
    response.status = 404;
    response.body_string = "Not found";

    return response;
}

/**
 * Actual entry point
 */
export function run(): void {
    run_user_kvs(userEntryPoint);
}
