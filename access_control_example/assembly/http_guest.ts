/**
 * AssemblyScript API for Fastly Terrarium guests.
 *
 * The main entrypoints are [[run_user]] and [[run_user_kvs]], with HTTP client capabilities
 * provided by [[Request]], and in-memory persistence provided by [[KVStore]].
 */

import "allocator/tlsf";

// eta-expand since `memory.allocate` is inlined
function malloc(size: usize): usize {
    return memory.allocate(size);
}

// eta-expand since `memory.free` is inlined
function free(ptr: usize): void {
    memory.free(ptr);
}

hostcall_init_mm(malloc, free);

/**
 * Function to start guest code.
 *
 * @param user_entrypoint Each request to the server will be passed to this function, and the
 * [[Response]] it returns will be written back to the end user.
 */
export function run_user(user_entrypoint: (req: Request) => Response): void {
    let req = Request.from_handle(RequestHandle.Incoming)
    let resp = user_entrypoint(req);
    resp.set_outgoing();
}

export function rng_next_u64(): u64 {
    return hostcall_rng_next_u64();
}

/**
 * Function to start guest code with a [[KVStore]] that persists between requests.
 *
 * @param user_entrypoint Each request to the server will be passed to this function along with the
 * mutable key-value store, and the [[Response]] it returns will be written back to the end user.
 */
export function run_user_kvs(user_entrypoint: (kvs: KVStore, req: Request) => Response): void {
    let req = Request.from_handle(RequestHandle.Incoming)
    let resp = user_entrypoint(new KVStore(), req);
    resp.set_outgoing();
}

/**
 * Convert a byte array into a string, performing lossy UTF-8 to UTF-16 transcoding.
 */
export function bytes_to_string(bytes: Array<u8>): string {
    return hostcall_utf8_to_utf16_lossy(bytes);
}

/**
 * Convert a string into a byte array, performing UTF-16 to UTF-8 transcoding.
 */
export function string_to_bytes(s: string): Array<u8> {
    return hostcall_utf16_to_utf8_lossy(s);
}

export function dns_query_raw(query_raw: Array<u8>): Array<u8> {
    return hostcall_dns_query_raw(query_raw);
}

export function dns_query_ip(name: string, ipv6: bool): Array<Array<u8>> {
    return hostcall_dns_query_ip(name, ipv6);
}

/**
 * An HTTP request.
 *
 * This is provided by the framework as an argument to the [[run_user]] and [[run_user_kvs]]
 * callbacks to represent the incoming request, and can also be passed to [[Request.send]] and
 * [[Request.send_async]] to send new requests out from the guest.
 */
@sealed
export class Request {
    private _method: string;
    private _url: string;
    private _body: Array<u8>;
    private _headers: Map<string, Array<string>>;
    // needed because we can't enumerate keys from `Map`
    private _set_header_keys: Array<string>;

    constructor(
        method: string,
        url: string,
    ) {
        this._method = method;
        this._url = url;
        this._body = null;
        this._headers = new Map();
        this._set_header_keys = new Array<string>();
    }

    /**
     * Get the method of the request, such as `GET` or `POST`.
     */
    get method(): string { return this._method; }
    /**
     * Set the method of the request, such as `GET` or `POST`.
     */
    set method(method: string) { this._method = method; }

    /**
     * Get the URL of the request. For incoming requests, this will be a path such as `/my_route`,
     * rather than a complete URL.
     */
    get url(): string { return this._url; }
    /**
     * Set the URL of the request.
     */
    set url(url: string) { this._url = url; }

    /**
     * Get the body of the request as bytes.
     */
    get body(): Array<u8> { return this._body; }
    /**
     * Set the body of the request as bytes.
     */
    set body(body: Array<u8>) { this._body = body; }

    /**
     * Get the body of the request as a string. This interprets the body as UTF-8 bytes, and lossily
     * converts it to UTF-16.
     */
    get body_string(): string {
        return bytes_to_string(this._body);
    }

    /**
     * Set the body of the request as a string. This lossily converts its argument into UTF-8 bytes.
     */
    set body_string(body_string: string) {
        this._body = string_to_bytes(body_string);
    }

    /**
     * Get the values associated with a header name.
     */
    get_header(key: string): string[] {
        if (this._headers.has(key)) {
            return this._headers.get(key);
        } else {
            return null;
        }
    }

    /**
     * Set the values associated with a header name. Any values that were previously set are
     * removed.
     */
    set_header(key: string, values: string[]): void {
        if (!this._headers.has(key)) {
            this._set_header_keys.push(key);
        }
        this._headers.set(key, values);
    }

    /**
     * Send a request synchronously.
     *
     * @returns The HTTP [[Response]], or `null` on error.
     */
    send(): Response {
        let req = this.to_handle();
        if (req === null) {
            return null;
        }

        let resp = hostcall_req_send(req);
        if (resp === ResponseHandle.Error) {
            return null;
        }

        return Response.from_handle(resp);
    }

    /**
     * Send a request asynchronously, returning immediately.
     *
     * @returns A [[PendingRequest]], or `null` on error.
     */
    send_async(): PendingRequest {
        let req = this.to_handle();
        if (req === null) {
            return null;
        }

        let pr = hostcall_req_send_async(req);
        if (pr === PendingRequestHandle.Error) {
            return null;
        }

        return new PendingRequest(pr);
    }

    private static from_handle(req_handle: RequestHandle): Request {
        let method = hostcall_req_get_method(req_handle);
        let url = hostcall_req_get_path(req_handle);

        let req = new Request(method, url);

        req._body = hostcall_req_get_body(req_handle);

        let keys = hostcall_req_get_headers(req_handle);
        for (let i = 0; i < keys.length; i++) {
            let key = keys[i];
            req.set_header(key, hostcall_req_get_header(req_handle, key));
        }

        return req;
    }

    private to_handle(): RequestHandle {
        let req = hostcall_req_create(this._method, this._url);
        if (req === RequestHandle.Error) {
            return req;
        }

        if (this._body !== null) {
            if (hostcall_req_set_body(req, this._body) === ValueStatus.Invalid) {
                return RequestHandle.Error;
            }
        }

        for (let i = 0; i < this._set_header_keys.length; i++) {
            let key = this._set_header_keys[i];
            if (hostcall_req_set_header(req, key, this._headers.get(key)) === ValueStatus.Invalid) {
                return RequestHandle.Error;
            }
        }

        return req;
    }
}

/**
 * An HTTP response.
 *
 * The framework expects this as the return value of the [[run_user]] and [[run_user_kvs]] callbacks
 * to represent the response sent back to the end user. This is also returned from HTTP client
 * requests made by the guest.
 */
@sealed
export class Response {
    private _status: u16;
    private _body: Array<u8>;
    private _headers: Map<string, Array<string>>;
    // needed because we can't enumerate keys from `Map`
    private _set_header_keys: Array<string>;
    // needed for `poll`
    private _is_ready: bool;
    // needed for `select`
    private _is_error: bool;
    private _pending_req: PendingRequest;

    constructor() {
        this._status = 200;
        this._body = null;
        this._headers = new Map();
        this._set_header_keys = new Array<string>();
        this._is_ready = true;
        this._is_error = false;
        this._pending_req = null;
    }

    /**
     * Get the HTTP status code of the response.
     */
    get status(): u16 { return this._status; }
    /**
     * Set the HTTP status code of the response.
     */
    set status(status: u16) { this._status = status; }

    /**
     * Get the body of the response as bytes.
     */
    get body(): Array<u8> { return this._body; }
    /**
     * Set the body of the response as bytes.
     */
    set body(body: Array<u8>) { this._body = body; }

    /**
     * Get the body of the response as a string. This interprets the body as UTF-8 bytes, and lossily
     * converts it to UTF-16.
     */
    get body_string(): string {
        return bytes_to_string(this._body);
    }

    /**
     * Set the body of the response as a string. This lossily converts its argument into UTF-8 bytes.
     */
    set body_string(body_string: string) {
        this._body = string_to_bytes(body_string);
    }

    /**
     * Get the values associated with a header name.
     */
    get_header(key: string): string[] {
        if (this._headers.has(key)) {
            return this._headers.get(key);
        } else {
            return null;
        }
    }

    /**
     * Set the values associated with a header name. Any values that were previously set are
     * removed.
     */
    set_header(key: string, values: string[]): void {
        if (!this._headers.has(key)) {
            this._set_header_keys.push(key);
        }
        this._headers.set(key, values);
    }

    /**
     * When returned from [[PendingRequest.poll]], this indicates whether the response is ready
     * (`true`), or still pending (`false`).
     */
    get is_ready(): u16 { return this._is_ready; }

    /**
     * When returned from [[select]], this indicates whether the request resulted in an error
     * (`true`), or was successfull (`false`).
     */
    get is_error(): bool { return this._is_error; }
    /**
     * When returned from [[select]], this indicates the corresponding [[PendingRequest]] that gave
     * rise to this response.
     */
    get pending_req(): PendingRequest { return this._pending_req; }

    private static from_handle(resp_handle: ResponseHandle, pending_req: PendingRequest = null): Response {
        let resp = new Response();
        resp._pending_req = pending_req;

        let status = hostcall_resp_get_response_code(resp_handle);
        let body = hostcall_resp_get_body(resp_handle);
        resp._status = status;
        resp._body = body;

        let keys = hostcall_resp_get_headers(resp_handle);
        for (let i = 0; i < keys.length; i++) {
            let key = keys[i];
            resp.set_header(key, hostcall_resp_get_header(resp_handle, key));
        }

        return resp;
    }

    private static not_ready(): Response {
        let resp = new Response();
        resp._is_ready = false;
    }

    private static select_error(pr: PendingRequest): Response {
        let resp = new Response();
        resp._is_error = true;
        resp._pending_req = pr;
        return resp;
    }

    private set_outgoing(): ValueStatus {
        if (hostcall_resp_set_response_code(ResponseHandle.Outgoing, this._status) === ValueStatus.Invalid) {
            return ValueStatus.Invalid;
        }

        if (this._body != null) {
            if (hostcall_resp_set_body(ResponseHandle.Outgoing, this._body) === ValueStatus.Invalid) {
                return ValueStatus.Invalid;
            }
        }

        for (let i = 0; i < this._set_header_keys.length; i++) {
            let key = this._set_header_keys[i];
            if (hostcall_resp_set_header(ResponseHandle.Outgoing, key, this._headers.get(key)) === ValueStatus.Invalid) {
                return ValueStatus.Invalid;
            }
        }

        return ValueStatus.Ok;
    }
}

/**
 * An HTTP request in progress; returned by [[Request.send_async]].
 */
@sealed
export class PendingRequest {
    private _handle: PendingRequestHandle;

    private constructor(handle: PendingRequestHandle) {
        this._handle = handle;
    }

    /**
     * Block until this request has completed.
     *
     * Once the request has completed, it is an error to use this object again.
     *
     * @returns The [[Response]] if successful, or `null` if the request failed.
     */
    wait(): Response {
        let resp_handle = hostcall_pending_req_wait(this._handle);
        if (resp_handle === ResponseHandle.Error) {
            return null;
        }

        return Response.from_handle(resp_handle);
    }

    /**
     * Check whether the request has completed. Returns immediately, although the response may not
     * be ready (see [[Response.is_ready]]).
     *
     * Once the request has completed, it is an error to use this object again.
     *
     * @returns The [[Response]] if the request has completed or is still in progress, or `null` if
     * the request failed.
     */
    poll(): Response {
        let resp_handle = hostcall_pending_req_poll(this._handle);
        if (resp_handle === ResponseHandle.Error) {
            return null;
        } else if (resp_handle === ResponseHandle.NotReady) {
            return Response.not_ready();
        } else {
            return Response.from_handle(resp_handle);
        }
    }

    equals(other: PendingRequest): bool {
        return other !== null && other._handle === this._handle;
    }
}

/**
 * Select from a list of [[PendingRequest]]s, blocking until one completes.
 *
 * The resulting [[Response]] will have the [[Response.is_error]] flag set to indicate whether the
 * request failed, and will have the [[Response.pending_req]] set to the request that completed.
 *
 * It is an error to use the completed request again, except to check for equality with other
 * [[PendingRequest]] objects.
 */
export function select(prs: Array<PendingRequest>): Response {
    let pr_handles = new Array<PendingRequestHandle>();
    for (let i = 0; i < prs.length; i++) {
        pr_handles.push(prs[i]._handle);
    }

    let pr_out = memory.allocate(4);

    let resp_handle = hostcall_pending_req_select(pr_handles, pr_out);
    let pr = new PendingRequest(load<PendingRequestHandle>(pr_out));

    if (resp_handle === ResponseHandle.Error) {
        return Response.select_error(pr);
    }

    return Response.from_handle(resp_handle, pr);
}

type RequestHandle = i32;

namespace RequestHandle {
    const Incoming = 0;
    const Error = -1;
}

type ResponseHandle = i32;

namespace ResponseHandle {
    const Outgoing = 0;
    const Error = -1;
    const NotReady = -2;
}

type PendingRequestHandle = i32;

namespace PendingRequestHandle {
    const Error = -1;
}

enum ValueStatus {
    Ok = 0,
    Invalid = 1,
}

/**
 * A key-value store that persists between incoming requests.
 */
@sealed
export class KVStore {
    private constructor() { }

    /**
     * Get the value for a key, or `null` if the key is not present.
     */
    get(key: string): Array<u8> {
        return hostcall_kvstore_get(key);
    }

    /**
     * Insert a value into the store at the given key.
     *
     * @returns `true` if the key was _not_ present before this call.
     */
    insert(key: string, value: Array<u8>): bool {
        return hostcall_kvstore_insert(key, value);
    }

    /**
     * Insert a value into the store at the given key if that key is not already present.
     *
     * @returns `true` if the key was _not_ present before this call.
     */
    upsert(key: string, value: Array<u8>): bool {
        return hostcall_kvstore_upsert(key, value);
    }

    /**
     * Append to the value at the given key if that key is present in the store. If not,
     * insert the value.
     *
     * @returns `true` if the key was _not_ present before this call.
     */
    append(key: string, value: Array<u8>): bool {
        return hostcall_kvstore_append(key, value);
    }

    /**
     * Remove a value from the store at the given key.
     *
     * @returns `true` if the key was removed.
     */
    remove(key: string): bool {
        return hostcall_kvstore_remove(key);
    }
}

/**
 * A point in time since the UNIX epoch, represented by the number of seconds since the epoch, and
 * the number of nanoseconds after that second.
 */
@sealed
export class Time {
    private _seconds: u64;
    private _subsec_nanos: u32;

    private constructor(seconds: u64, subsec_nanos: u32) {
        this._seconds = seconds;
        this._subsec_nanos = subsec_nanos;
    }

    /**
     * Number of seconds this `Time` represents since the UNIX epoch.
     */
    get seconds(): u64 { return this._seconds; }

    /**
     * Number of nanoseconds after the second represented by this `Time`.
     */
    get subsec_nanos(): u32 { return this._subsec_nanos; }

    /**
     * Get the current time.
     */
    static now(): Time {
        let subsec_nanos_out = memory.allocate(4);
        let seconds = hostcall_time_now(subsec_nanos_out);
        let subsec_nanos = load<u32>(subsec_nanos_out);
        return new Time(seconds, subsec_nanos);
    }

    @operator("==")
    private static __eq(left: Time, right: Time): bool {
        if (left === right) {
            return true;
        }
        if (left === null || right === null) {
            return false;
        }

        return left.seconds === right.seconds && left.subsec_nanos === right.subsec_nanos;
    }

    @operator("!=")
    private static __ne(left: Time, right: Time): bool {
        return !this.__eq(left, right);
    }


    @operator(">")
    private static __gt(left: Time, right: Time): bool {
        if (left === right || left === null || right === null) {
            return false;
        }

        if (left.seconds > right.seconds) {
            return true;
        }

        if (left.seconds === right.seconds) {
            return left.subsec_nanos > right.subsec_nanos;
        }

        return false;
    }

    @operator(">=")
    private static __gte(left: Time, right: Time): bool {
        if (left === right) return true;
        if (left === null || right === null) return false;
        return this.__eq(left, right) || this.__gt(left, right);
    }

    @operator("<")
    private static __lt(left: Time, right: Time): bool {
        if (left === right || left === null || right === null) return false;
        return !this.__gte(left, right);
    }

    @operator("<=")
    private static __lte(left: Time, right: Time): bool {
        if (left === right) return true;
        if (left === null || right === null) return false;
        return !this.__gt(left, right);
    }
}

declare function hostcall_dns_query_raw(query_raw: Array<u8>): Array<u8>;
declare function hostcall_dns_query_ip(name: string, ipv6: bool): Array<Array<u8>>;
declare function hostcall_init_mm(malloc: (size: usize) => usize, free: (ptr: usize) => void): void;
declare function hostcall_kvstore_get(key: string): Array<u8>;
declare function hostcall_kvstore_insert(key: string, value: Array<u8>): bool;
declare function hostcall_kvstore_remove(key: string): bool;
declare function hostcall_kvstore_upsert(key: string, value: Array<u8>): bool;
declare function hostcall_kvstore_append(key: string, value: Array<u8>): bool;
declare function hostcall_pending_req_wait(pr: PendingRequestHandle): ResponseHandle;
declare function hostcall_pending_req_poll(pr: PendingRequestHandle): ResponseHandle;
declare function hostcall_pending_req_select(prs: Array<PendingRequestHandle>, pr_out: usize): ResponseHandle;
declare function hostcall_req_create(method: string, url: string): RequestHandle;
declare function hostcall_req_get_body(req: RequestHandle): Array<u8>;
declare function hostcall_req_get_header(req: RequestHandle, name: string): string[];
declare function hostcall_req_get_headers(req: RequestHandle): string[];
declare function hostcall_req_get_method(req: RequestHandle): string;
declare function hostcall_req_get_path(req: RequestHandle): string;
declare function hostcall_req_send(req: RequestHandle): ResponseHandle;
declare function hostcall_req_send_async(req: RequestHandle): PendingRequestHandle;
declare function hostcall_req_set_body(req: RequestHandle, body: Array<u8>): ValueStatus;
declare function hostcall_req_set_header(req: RequestHandle, name: string, values: string[]): ValueStatus;
declare function hostcall_resp_get_body(resp: ResponseHandle): Array<u8>;
declare function hostcall_resp_get_header(resp: ResponseHandle, name: string): string[];
declare function hostcall_resp_get_headers(resp: ResponseHandle): string[];
declare function hostcall_resp_get_response_code(resp: ResponseHandle): u16;
declare function hostcall_resp_set_body(resp: ResponseHandle, body: Array<u8>): ValueStatus;
declare function hostcall_resp_set_header(resp: ResponseHandle, name: string, values: string[]): ValueStatus;
declare function hostcall_resp_set_response_code(resp: ResponseHandle, code: u16): ValueStatus;
declare function hostcall_rng_next_u64(): u64;
declare function hostcall_time_now(subsec_nanos_out: usize): u64;
declare function hostcall_utf16_to_utf8_lossy(utf16: string): Array<u8>;
declare function hostcall_utf8_to_utf16_lossy(utf8: Array<u8>): string;
