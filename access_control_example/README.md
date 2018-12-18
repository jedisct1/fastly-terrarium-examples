# Access control example

This example handles user registration and authentication.

A web form allows users to register and to securely sign in with a login and password, without ever sending passwords to the server.

## What this examples shows

- User authentication can be done at the edge, so that origins only receive traffic from authenticated users
- The exact same WebAssembly code can be shared by code running server-side (Terrarium), and client-side (a web browser)
- How to use AssemblyScript and the Terrarium guest API
- How to share data between AssemblyScript, WebAssembly and JavaScript.

## High-level protocol overview

The protocol assumes that the client and the server communicate over a secure channel. Terrarium is only accessible over TLS.

### User registration

- The client picks a `salt` indistinguishable from random
- The client derives a secret scalar `sk` from the password and `salt` using a key stretching function
- The client computes a public key `pk` using the secret scalar `sk`
- The client sends `(username, pk, salt)` to the server
- The server checks that `username` hasn't already been registered, and stores `(username, pk, salt)`.

```text
{server}                                                                  {client}

(username, pk, salt) ---------------------------------------------------->
```

### User authentication

- The clients sends `username` to the server
- The server picks a `nonce` indistinguishable from random
- If `username` is present in the database, the server retrieves the corresponding `salt`
- If `username` is not present in the database, the server computes `salt = H(hk, username)` with `H` being a keyed hash function and `hk` a long-term secret
- The server sends `(salt, nonce)` to the client
- The client derives a secret scalar from the password and `salt` using a key stretching function: `sk = KDF(password, salt)`
- The client picks a `salt'` indistinguishable from random
- The client derives a second secret scalar from the password and `salt'` using a key stretching function: `sk' = KDF(password, salt')`
- The client computes a second public key `pk'` using the secret scalar `sk'`
- The client computes a signature `s = S(sk, domain || username || nonce || salt' || pk')`, with `domain` being a constant, application-specific string
- The client sends `(username, salt', pk', s)` to the server
- The server retrieves the `nonce` previously sent, as well as the stored `salt` and `pk` values for the given user
- The server verifies that `s` is a valid signature for `(domain || username || nonce || salt' || pk')` using the public key `pk` and rejects the authentication attempt if it doesn't verify
- The server replaces the stored `salt` value with `salt'` and `pk` with `pk'`.

```text
{server}                                                                  {client}

username ---------------------------------------------------------------->

        <----------------------------------------------------------- (salt, nonce)

(username, salt', pk',
  S(sk, (domain || username ||
        nonce || salt' || pk'))) ---------------------------------------->

        <------------------------------------------ V(pk, (domain || username ||
                                                           nonce || salt' || pk'))
```

The salt can be kept secret using a slight variation of this protocol, where a second salt is computed from the server-stored salt and the password using an Oblivious PRF, as proposed in the [OPAQUE](https://tools.ietf.org/html/draft-krawczyk-cfrg-opaque-00) protocol.
The included crypto library implements the required primitives to do so.

## Code overview

### assembly/{crypto.ts, precomp.ts}

This code is used both by the JavaScript client code and by the AssemblyScript running on Terrarium. It implements the following cryptographic primitives in AssemblyScript:

- The EdDSA signature scheme
- The HMAC-SHA-512 keyed MAC.

Functions exported by this module can be called by the main server code using their native interface, since both are written in the same language.

The client-side logic, however, is written in JavaScript. While JavaScript can load that code as a WebAssembly module, it doesn't use the same memory model.

Since a WebAssembly module cannot access its host's memory, in order to call a function originally written in AssemblyScript from JavaScript, a special API has to be used. That API asks AssemblyScript to reserve internal memory, and return its location, to which JavaScript can copy its data before calling the actual function.

Reciprocally, data being returned by the WebAssembly module needs to be copied into a native JavaScript object in order to be easy to use.

This is the purpose of the `wasm.newArray()` and `wasm.getArray()` functions, that are used by virtually all JavaScript <-> AssemblyScript calls in this example.

### assembly/utils.ts

Simple helper functions to convert between array types, and prefix strings with their length in order to add domain separation.

### assembly/index.ts

Main server code, exposing three HTTP API endpoints:

- `/signup`
- `/login-get-salt-and-nonce`
- `/login`

At the time of writing, AssemblyScript doesn't support JSON. Considering this limitation, and the fact that some of the data (nonces, public keys) cannot be represented as JSON values without additional encoding, exchanged values are simply concatenated in an unambiguous way.

User data is stored using the KV store API, and keys have the following structure: `(<data type> || username)`. This requires user names to be valid UTF-8 sequences, a condition that is checked for every access to the KV store.

#### Signup API

The `upsert` KV store function is used to store `(salt || pk)` in a key named `("salt_and_pk|" || username)`. This function will fail and return `false` if an entry is already present.

#### Login/get salt and nonce

The salt is required by a client to recover the secret scalar from any device.

If an entry for the key `("salt_and_pk|" || username)` is present, that salt is returned. If it isn't, truncated output of the `HMAC-SHA-512(username, hash_key)` function is returned to mitigate user enumeration. Note that this is only a mitigation, as access to the KV store are not guaranteed to be constant-time.

`hash_key` is an internal secret key, created on-demand, and written to the KV store with the `hash_key` key.

A random nonce is generated, and stored independently, as `(nonce || ts)` with `("nonce_and_ts|" || username)`, with `ts` being the current time stamp.

Since a single nonce is stored, an attacker could repeatedly hit this endpoint to exploit the race between calls to `/login-get-salt-and-nonce` and `/login`, and prevent a user from logging in. As a mitigation, a new nonce will not overwrite the previous value if that one was generated less than 1 second ago.
This would not be necessary if both steps were made using the same connection. This is the purpose of the `ts` value stored along with the nonce.

#### Login

The second step of the login process retrieves the public key from the `("salt_and_pk|" || username)` key, as well as the nonce.

If the database doesn't contain these, authentication will fail.

It then constructs the challenge `(domain || username || nonce || salt' || pk')` and verifies that the received signature is valid for that challenge.

If this is the case, the value for the `("salt_and_pk|" || username)` key is overwritten with `(salt' || pk')`. Salts are updated after each login in order to mitigate precomputation attacks targeting specific users. This is not required, though, as this implies two calls to a CPU-intensive key stretching function. Although these can be parallelized, a client with constrained resources can set `salt' = salt` and `pk' = pk`.

### assets/optimized.wasm

Precompiled WebAssembly code for `assembly/crypto.ts`, so that it can be loaded as a module by the JavaScript code.

### assets/acl.js

A simple web application showing a client-side implementation of the protocol.

It requires a modern web browser, with support for ES6, CSS grids, and WebAssembly.

As mentioned above, calls to WebAssembly functions require copies between the WebAssembly memory space, and native JavaScript objects. In order to do so, as well as properly load the module, `acl.js` includes the `loader` module from the AssemblyScript project, from which this example uses the following functions of:

- `instantiateBuffer()`: to load the module and initialize its environment
- `newArray()`: to copy a JavaScript value to a WebAssembly internal memory location
- `getArray()`: for the opposite operation.

Key stretching is made using the WebCrypto API. As this operation is not required by the server, a WebAssembly implementation is not required either.

### assets/{index.html, styles.rss}

Static HTML code and style sheet.
