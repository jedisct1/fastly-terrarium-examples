import { run_user_kvs, Request, KVStore, Response, Time } from "./http_guest";
import { hmac, SIGN_BYTES, SIGN_PUBLICKEYBYTES, signVerify } from "./crypto";
import {
    bytes_decode, bytes_encode, bytes_next, generic_array_to_u8_array, get_random,
    key_for, kvs_get, kvs_init, kvs_insert, kvs_upsert, str_encode,
    u8_array_copy, u8_array_to_generic_array, load64, store64, is_utf8, uncachedResponse
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
 * A pseudo-random salt is returned for nonexistent users.
 * Since it should be deterministic, a key is created and
 * persisted, if necessary.
 */
function get_hash_key(): Uint8Array {
    let key = kvs_get("hash_key");
    if (!key) {
        key = new Uint8Array(32);
        get_random(key);
        kvs_insert("hash_key", key);
    }
    return key;
}

/**
 * login-get-salt-and-nonce API
 *
 * Return the salt for a user name, as well as a random nonce.
 * If the user doesn't exist, we still return a tuple, but
 * with a salt derived from the user name and the hmac key.
 *
 * Note that access to the KV store is not constant-time,
 * so user enumeration remains possible.
 *
 * In: username
 * Out: salt || nonce
 *
 * @param req HTTP Request
 */
function login_get_salt_and_nonce(req: Request): Response {
    let response = uncachedResponse();
    response.status = 400;

    let body = generic_array_to_u8_array(req.body);
    let username = bytes_decode(body);
    if (!username) {
        response.body_string = "Empty username";
        return response;
    }

    let now = Time.now().seconds as u64;
    let salt_and_nonce = new Uint8Array(32 + 32);
    let nonce = salt_and_nonce.subarray(32);
    get_random(nonce);

    let nonce_and_ts_key = key_for("nonce_and_ts", username);
    let nonce_and_ts = kvs_get(nonce_and_ts_key);
    if (nonce_and_ts) {
        let ts = load64(nonce_and_ts, 32);
        if (ts > now || now - ts > 3) {
            nonce_and_ts = null;
        }
    }
    if (nonce_and_ts) {
        u8_array_copy(nonce, nonce_and_ts.subarray(0, 32));
    } else {
        nonce_and_ts = new Uint8Array(32 + 8);
        u8_array_copy(nonce_and_ts, nonce);
        store64(nonce_and_ts, 32, now);
    }
    kvs_insert(nonce_and_ts_key, nonce_and_ts);

    let hash_key = get_hash_key();
    let salt = hmac(username, hash_key).subarray(0, 32);
    let salt_and_pk_key = key_for("salt_and_pk", username);
    let salt_and_pk = kvs_get(salt_and_pk_key);
    if (salt_and_pk) {
        salt = salt_and_pk.subarray(0, 32);
    }
    u8_array_copy(salt_and_nonce, salt);

    response.body = u8_array_to_generic_array(salt_and_nonce);
    response.status = 200;

    return response;
}

/**
 * login API
 *
 * Check that the client sent a valid signature for
 * c = (domain || username || nonce || salt2 || pk2) using
 * the stored public key for that user,
 * and onsider it authenticated if verification succeeds.
 *
 * If this is the case, replace the stored (salt, pk)
 * with (salt2, pk2).
 *
 * IN: username || salt2 || pk2 || S(pk, c)
 * OUT: HTTP status code
 *
 * @param req HTTP Request
 */
function login(req: Request): Response {
    let response = uncachedResponse();
    response.status = 400;

    let body = generic_array_to_u8_array(req.body);
    let username = bytes_decode(body);
    if (!username) {
        return response;
    }

    let nonce_and_ts_key = key_for("nonce_and_ts", username);
    let nonce_and_ts = kvs_get(nonce_and_ts_key);
    if (!nonce_and_ts) {
        response.body_string = "Missing nonce";
        response.status = 403;
        return response;
    }
    let nonce = nonce_and_ts.subarray(0, 32);

    let salt2_and_pk2_and_signature = bytes_next(body);

    let salt2 = new Uint8Array(32);
    u8_array_copy(salt2, salt2_and_pk2_and_signature.subarray(0, 32));
    let pk2 = new Uint8Array(SIGN_PUBLICKEYBYTES);
    u8_array_copy(pk2, salt2_and_pk2_and_signature.subarray(32, 32 + SIGN_PUBLICKEYBYTES));
    let signature = new Uint8Array(SIGN_BYTES);
    u8_array_copy(signature, salt2_and_pk2_and_signature.subarray(32 + SIGN_PUBLICKEYBYTES));

    let salt_and_pk_key = key_for("salt_and_pk", username);
    let salt_and_pk = kvs_get(salt_and_pk_key);
    if (!salt_and_pk) {
        salt_and_pk = new Uint8Array(32 + SIGN_PUBLICKEYBYTES + 1);
        response.body_string = "Incorrect (login, password) pair";
        response.status = 401;
        return response;
    }
    let pk = new Uint8Array(SIGN_PUBLICKEYBYTES);
    u8_array_copy(pk, salt_and_pk.subarray(32, 32 + SIGN_PUBLICKEYBYTES));

    let domain_bin = str_encode(DOMAIN);
    let username_bin = bytes_encode(username);
    let challenge = new Uint8Array(domain_bin.length + username_bin.length + nonce.length + salt2.length + pk2.length);
    u8_array_copy(challenge, domain_bin);
    u8_array_copy(challenge.subarray(domain_bin.length), username_bin);
    u8_array_copy(challenge.subarray(domain_bin.length + username_bin.length), nonce);
    u8_array_copy(challenge.subarray(domain_bin.length + username_bin.length + nonce.length), salt2);
    u8_array_copy(challenge.subarray(domain_bin.length + username_bin.length + nonce.length + salt2.length), pk2);

    let verified = signVerify(challenge, signature, pk);
    if (!verified) {
        response.body_string = "Incorrect (login, password) pair";
        response.status = 401;
        return response;
    }

    u8_array_copy(salt_and_pk, salt2);
    u8_array_copy(salt_and_pk, pk2, 32);
    kvs_insert(salt_and_pk_key, salt_and_pk);
    response.body_string = "Access allowed";
    response.status = 200;

    return response;
}

/**
 * /signup API
 *
 * Register a new user by storing its name, salt an public key
 * in the database.
 *
 * IN: username || pk || salt
 * OUT: HTTP status code
 *
 * @param req HTTP Request
 */
function signup(req: Request): Response {
    let response = uncachedResponse();
    response.status = 400;

    let body = generic_array_to_u8_array(req.body);
    let username = bytes_decode(body);
    if (!username || username.length >= MAX_USERNAME_LENGTH || !is_utf8(username)) {
        response.body_string = "Invalid username";
        return response;
    }
    let pk_and_salt = bytes_next(body);
    let pk = pk_and_salt.subarray(0, SIGN_PUBLICKEYBYTES);
    let salt = pk_and_salt.subarray(SIGN_PUBLICKEYBYTES);
    if (!username) {
        return response;
    }

    let salt_and_pk_key = key_for("salt_and_pk", username);
    let salt_and_pk = new Uint8Array(32 + SIGN_PUBLICKEYBYTES);
    u8_array_copy(salt_and_pk, salt);
    u8_array_copy(salt_and_pk, pk, 32);
    if (kvs_upsert(salt_and_pk_key, salt_and_pk) == false) {
        response.body_string = "An account with that name already exists";
        response.status = 403;
        return response;
    }
    response.status = 200;

    return response;
}

/**
 * Entry point callback
 * @param _kvs KVStore object
 * @param req HTTP request
 */
function user_entrypoint(_kvs: KVStore, req: Request): Response {
    kvs_init(_kvs);
    let url = req.url;
    let method = req.method;
    if (method == "POST") {
        if (req.body.length >= MAX_BODY_LENGTH) {
            let response = uncachedResponse();
            response.status = 413;
            response.body_string = "Request too large";
            return response;
        }
        if (url == "/login-get-salt-and-nonce") {
            return login_get_salt_and_nonce(req);
        } else if (url == "/login") {
            return login(req);
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
    run_user_kvs(user_entrypoint);
}
