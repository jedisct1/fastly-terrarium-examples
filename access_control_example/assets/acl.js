"use strict";
/* jshint esversion: 6 */

const KDF_ITERATIONS = 100000;
const DOMAIN = "example.wasm.fastly-terrarium.com";

function show(sel) {
    document.querySelectorAll(sel).forEach(node => node.style.display = "grid");
}

function hide(sel) {
    document.querySelectorAll(sel).forEach(node => node.style.display = "none");
}

function disable(sel) {
    document.querySelectorAll(sel).forEach(node => node.setAttribute("disabled", ""));
}

function enable(sel) {
    document.querySelectorAll(sel).forEach(node => node.removeAttribute("disabled"));
}

function clearError(sel) {
    const node = document.querySelector(sel);
    node.style.display = "none";
    if (node.firstChild) {
        node.removeChild(node.firstChild)
    };
}

function error(sel, s) {
    const node = document.querySelector(sel);
    if (node.firstChild) {
        node.removeChild(node.firstChild)
    };
    node.appendChild(document.createTextNode(s));
    node.style.display = "block";
}

function strToBytes(str) {
    const text_bytes = new TextEncoder("utf-8").encode(str);
    const blen = text_bytes.length;
    const bytes = new Uint8Array(2 + blen);
    bytes[0] = blen & 0xff;
    bytes[1] = (blen >>> 8) & 0xff;
    bytes.set(text_bytes, 2);

    return bytes;
}

function bytesToStr(bytes) {
    const remaining = bytes.length;
    if (remaining < 2) {
        throw "invalid length";
    }
    const blen = bytes[0] | (bytes[1] << 8);
    const consumed = 2 + blen;
    if (remaining < consumed) {
        throw "inconsistent length";
    }
    const str = new TextDecoder("utf-8").decode(bytes.subarray(2, 2 + blen));

    return {
        consumed,
        str
    }
}

function signupInit() {
    const login_link = document.querySelector("#signup a");
    login_link.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        login();
        return false;
    });

    const node_signup_form = document.querySelector("#signup form");
    node_signup_form.addEventListener("submit", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const username = document.querySelector("#signup .username").value.trim();
        const password = document.querySelector("#signup .password").value.trim();
        if (!username || !password) {
            return;
        }
        disable("#signup input[type=submit]");
        clearError("#signup .error");

        const username_bin = strToBytes(username);
        const password_bin = strToBytes(password);
        const salt = new Uint8Array(32);
        crypto.getRandomValues(salt);
        (async() => {
            const password_key = await crypto.subtle.importKey("raw", password_bin, "PBKDF2", false, ["deriveBits"]);
            const kdfParams = {
                name: "PBKDF2",
                hash: "SHA-512",
                salt,
                iterations: KDF_ITERATIONS
            };
            const seed = new Uint8Array(await crypto.subtle.deriveBits(kdfParams, password_key, 8 * wasm.SIGN_SEEDBYTES));
            let seed_wasm = wasm.newArray(seed);
            const keypair_wasm = wasm.signKeypairFromSeed(seed_wasm);
            const pk_wasm = wasm.signPublicKey(keypair_wasm);
            const pk = wasm.getArray(Uint8Array, pk_wasm);
            const username_and_pk_and_salt = new Uint8Array(username_bin.length + pk.length + salt.length);
            username_and_pk_and_salt.set(username_bin);
            username_and_pk_and_salt.set(pk, username_bin.length);
            username_and_pk_and_salt.set(salt, username_bin.length + pk.length);
            const response = await (await fetch("signup", {
                body: username_and_pk_and_salt,
                method: "POST",
                mode: "no-cors"
            }));
            enable("#signup input[type=submit]");
            if (response.status === 403) {
                error("#signup .error", "An account with that name already exists");
                return;
            }
            if (!response.ok) {
                error("#signup .error", "Internal error");
                return;
            }
            login();
        })();
        return false;
    });
}

function signup() {
    if (!self.signup_initialized) {
        signupInit();
        self.signup_initialized = true;
    }
    hide("#login");
    clearError("#signup .error");
    show("#signup");
    document.querySelector("#signup .username").focus();
}

function loginInit() {
    const signup_link = document.querySelector("#login a");
    signup_link.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();
        signup();
        return false;
    });

    const node_login_form = document.querySelector("#login form");
    node_login_form.addEventListener("submit", (e) => {
        e.preventDefault();
        e.stopPropagation();
        const username = document.querySelector("#login .username").value.trim();
        const password = document.querySelector("#login .password").value.trim();
        if (!username || !password) {
            return;
        }
        disable("#login input[type=submit]");
        clearError("#login .error");

        const username_bin = strToBytes(username);
        const password_bin = strToBytes(password);

        async function getKeypairForSaltAndPassword(salt) {
            const password_key = await crypto.subtle.importKey("raw", password_bin, "PBKDF2", false, ["deriveBits"]);
            const kdf_params = {
                name: "PBKDF2",
                hash: "SHA-512",
                salt,
                iterations: KDF_ITERATIONS
            };
            const seed = new Uint8Array(await crypto.subtle.deriveBits(kdf_params, password_key, 8 * wasm.SIGN_SEEDBYTES));

            let seed_wasm = wasm.newArray(seed);
            const keypair_wasm = wasm.signKeypairFromSeed(seed_wasm);

            return wasm.getArray(Uint8Array, keypair_wasm);
        }

        (async() => {
            const salt_and_nonce = new Uint8Array(await (await fetch("login-get-salt-and-nonce", {
                body: username_bin,
                method: "POST",
                mode: "no-cors"
            })).arrayBuffer());
            if (salt_and_nonce.length !== 32 + 32) {
                enable("#login input[type=submit]");
                throw "Unexpected response";
                return;
            }
            const salt = salt_and_nonce.subarray(0, 32);
            const nonce = salt_and_nonce.subarray(32);

            const salt2 = new Uint8Array(32);
            crypto.getRandomValues(salt2);

            const keypair = await getKeypairForSaltAndPassword(salt);
            const keypair_wasm = wasm.newArray(keypair);
            const pkWasm = wasm.signPublicKey(keypair_wasm);
            const keypair2 = await getKeypairForSaltAndPassword(salt2);
            const keypair2_wasm = wasm.newArray(keypair2);
            const pk2_wasm = wasm.signPublicKey(keypair2_wasm);
            const pk2 = wasm.getArray(Uint8Array, pk2_wasm);

            const challenge_ = [];
            challenge_.push(...strToBytes(DOMAIN));
            challenge_.push(...username_bin);
            challenge_.push(...nonce);
            challenge_.push(...salt2);
            challenge_.push(...pk2);
            const challenge = new Uint8Array(challenge_);

            const z = new Uint8Array(wasm.SIGN_RANDBYTES);
            crypto.getRandomValues(z);
            const signature_wasm = wasm.sign(wasm.newArray(challenge), keypair_wasm, z);
            if (wasm.signVerify(wasm.newArray(challenge), signature_wasm, pkWasm) != true) {
                throw "Signature doesn't verify";
            }

            const signature = wasm.getArray(Uint8Array, signature_wasm);
            const username_and_salt2_and_pk2_and_signature = new Uint8Array(username_bin.length + salt2.length + pk2.length + wasm.SIGN_BYTES);
            username_and_salt2_and_pk2_and_signature.set(username_bin);
            username_and_salt2_and_pk2_and_signature.set(salt2, username_bin.length);
            username_and_salt2_and_pk2_and_signature.set(pk2, username_bin.length + salt2.length);
            username_and_salt2_and_pk2_and_signature.set(signature, username_bin.length + salt2.length + pk2.length);
            const response = await (await fetch("login", {
                body: username_and_salt2_and_pk2_and_signature,
                method: "POST",
                mode: "no-cors",
            }));
            enable("#login input[type=submit]");
            if (response.status === 401) {
                error("#login .error", "Access denied");
                return;
            }
            if (!response.ok) {
                error("#login .error", "Internal error");
                return;
            }
            console.log("Logged in!");
            hide("#login");
            show("#loggedin");
        })();
        return false;
    }, false);
}

function login() {
    if (!self.login_initialized) {
        loginInit();
        self.login_initialized = true;
    }
    hide("#signup");
    clearError("#login .error");
    show("#login");
    document.querySelector("#login .username").focus();
}

let wasm = null;

const loader = (function() {
    let exports = {};

    const hasBigInt64 = typeof BigUint64Array !== "undefined";

    /** Gets a string from an U32 and an U16 view on a memory. */
    function getStringImpl(U32, U16, ptr) {
        var dataLength = U32[ptr >>> 2];
        var dataOffset = (ptr + 4) >>> 1;
        var dataRemain = dataLength;
        var parts = [];
        const chunkSize = 1024;
        while (dataRemain > chunkSize) {
            let last = U16[dataOffset + chunkSize - 1];
            let size = last >= 0xD800 && last < 0xDC00 ? chunkSize - 1 : chunkSize;
            let part = U16.subarray(dataOffset, dataOffset += size);
            parts.push(String.fromCharCode.apply(String, part));
            dataRemain -= size;
        }
        return parts.join("") + String.fromCharCode.apply(String, U16.subarray(dataOffset, dataOffset + dataRemain));
    }

    /** Prepares the base module prior to instantiation. */
    function preInstantiate(imports) {
        var baseModule = {};

        // add the internal abort function that is called when an assertion fails or an error is thrown
        if (!imports.env) imports.env = {};
        if (!imports.env.abort) imports.env.abort = function abort(mesg, file, line, colm) {
            var memory = baseModule.memory || imports.env.memory; // prefer exported, otherwise try imported
            function getString(memory, ptr) {
                if (!memory) return "<yet unknown>";
                var buffer = memory.buffer;
                return getStringImpl(new Uint32Array(buffer), new Uint16Array(buffer), ptr);
            }
            throw Error("abort: " + getString(memory, mesg) + " at " + getString(memory, file) + ":" + line + ":" + colm);
        }

        return baseModule;
    }

    /** Prepares the final module once instantiation is complete. */
    function postInstantiate(baseModule, instance) {
        var rawExports = instance.exports;
        var memory = rawExports.memory;
        var memory_allocate = rawExports["memory.allocate"];
        var memory_fill = rawExports["memory.fill"];
        var memory_free = rawExports["memory.free"];
        var table = rawExports.table;
        var setargc = rawExports._setargc || function() {};

        // Provide views for all sorts of basic values
        var buffer, I8, U8, I16, U16, I32, U32, F32, F64, I64, U64;

        /** Updates memory views if memory has grown meanwhile. */
        function checkMem() {
            // see: https://github.com/WebAssembly/design/issues/1210
            if (buffer !== memory.buffer) {
                buffer = memory.buffer;
                I8 = new Int8Array(buffer);
                U8 = new Uint8Array(buffer);
                I16 = new Int16Array(buffer);
                U16 = new Uint16Array(buffer);
                I32 = new Int32Array(buffer);
                U32 = new Uint32Array(buffer);
                if (hasBigInt64) {
                    I64 = new BigInt64Array(buffer);
                    U64 = new BigUint64Array(buffer);
                }
                F32 = new Float32Array(buffer);
                F64 = new Float64Array(buffer);
            }
        }
        checkMem();

        /** Allocates a new string in the module's memory and returns its pointer. */
        function newString(str) {
            var dataLength = str.length;
            var ptr = memory_allocate(4 + (dataLength << 1));
            var dataOffset = (4 + ptr) >>> 1;
            checkMem();
            U32[ptr >>> 2] = dataLength;
            for (let i = 0; i < dataLength; ++i) U16[dataOffset + i] = str.charCodeAt(i);
            return ptr;
        }

        baseModule.newString = newString;

        /** Gets a string from the module's memory by its pointer. */
        function getString(ptr) {
            checkMem();
            return getStringImpl(U32, U16, ptr);
        }

        baseModule.getString = getString;

        function computeBufferSize(byteLength) {
            const HEADER_SIZE = 8;
            return 1 << (32 - Math.clz32(byteLength + HEADER_SIZE - 1));
        }

        /** Creates a new typed array in the module's memory and returns its pointer. */
        function newArray(view, length, unsafe) {
            var ctor = view.constructor;
            if (ctor === Function) { // TypedArray constructor created in memory
                ctor = view;
                view = null;
            } else { // TypedArray instance copied into memory
                if (length === undefined) length = view.length;
            }
            var elementSize = ctor.BYTES_PER_ELEMENT;
            if (!elementSize) throw Error("not a typed array");
            var byteLength = elementSize * length;
            var ptr = memory_allocate(12); // TypedArray header
            var buf = memory_allocate(computeBufferSize(byteLength)); // ArrayBuffer
            checkMem();
            U32[ptr >>> 2] = buf; // .buffer
            U32[(ptr + 4) >>> 2] = 0; // .byteOffset
            U32[(ptr + 8) >>> 2] = byteLength; // .byteLength
            U32[buf >>> 2] = byteLength; // .byteLength
            U32[(buf + 4) >>> 2] = 0; // 0
            if (view) {
                new ctor(buffer, buf + 8, length).set(view);
                if (view.length < length && !unsafe) {
                    let setLength = elementSize * view.length;
                    memory_fill(buf + 8 + setLength, 0, byteLength - setLength);
                }
            } else if (!unsafe) {
                memory_fill(buf + 8, 0, byteLength);
            }
            return ptr;
        }

        baseModule.newArray = newArray;

        /** Gets a view on a typed array in the module's memory by its pointer. */
        function getArray(ctor, ptr) {
            var elementSize = ctor.BYTES_PER_ELEMENT;
            if (!elementSize) throw Error("not a typed array");
            checkMem();
            var buf = U32[ptr >>> 2];
            var byteOffset = U32[(ptr + 4) >>> 2];
            var byteLength = U32[(ptr + 8) >>> 2];
            return new ctor(buffer, buf + 8 + byteOffset, (byteLength - byteOffset) / elementSize);
        }

        baseModule.getArray = getArray;

        /** Frees a typed array in the module's memory. Must not be accessed anymore afterwards. */
        function freeArray(ptr) {
            checkMem();
            var buf = U32[ptr >>> 2];
            memory_free(buf);
            memory_free(ptr);
        }

        baseModule.freeArray = freeArray;

        /**
         * Creates a new function in the module's table and returns its pointer. Note that only actual
         * WebAssembly functions, i.e. as exported by the module, are supported.
         */
        function newFunction(fn) {
            if (typeof fn.original === "function") fn = fn.original;
            var index = table.length;
            table.grow(1);
            table.set(index, fn);
            return index;
        }

        baseModule.newFunction = newFunction;

        /** Gets a function by its pointer. */
        function getFunction(ptr) {
            return wrapFunction(table.get(ptr), setargc);
        }

        baseModule.getFunction = getFunction;

        // Demangle exports and provide the usual utility on the prototype
        return demangle(rawExports, Object.defineProperties(baseModule, {
            I8: {
                get: function() {
                    checkMem();
                    return I8;
                }
            },
            U8: {
                get: function() {
                    checkMem();
                    return U8;
                }
            },
            I16: {
                get: function() {
                    checkMem();
                    return I16;
                }
            },
            U16: {
                get: function() {
                    checkMem();
                    return U16;
                }
            },
            I32: {
                get: function() {
                    checkMem();
                    return I32;
                }
            },
            U32: {
                get: function() {
                    checkMem();
                    return U32;
                }
            },
            I64: {
                get: function() {
                    checkMem();
                    return I64;
                }
            },
            U64: {
                get: function() {
                    checkMem();
                    return U64;
                }
            },
            F32: {
                get: function() {
                    checkMem();
                    return F32;
                }
            },
            F64: {
                get: function() {
                    checkMem();
                    return F64;
                }
            }
        }));
    }

    /** Wraps a WebAssembly function while also taking care of variable arguments. */
    function wrapFunction(fn, setargc) {
        var wrap = (...args) => {
                setargc(args.length);
                return fn(...args);
            }
            // adding a function to the table with `newFunction` is limited to actual WebAssembly functions,
            // hence we can't use the wrapper and instead need to provide a reference to the original
        wrap.original = fn;
        return wrap;
    }

    /** Instantiates an AssemblyScript module using the specified imports. */
    function instantiate(module, imports) {
        return postInstantiate(
            preInstantiate(imports || (imports = {})),
            new WebAssembly.Instance(module, imports)
        );
    }

    exports.instantiate = instantiate;

    /** Instantiates an AssemblyScript module from a buffer using the specified imports. */
    function instantiateBuffer(buffer, imports) {
        return instantiate(new WebAssembly.Module(buffer), imports);
    }

    exports.instantiateBuffer = instantiateBuffer;

    /** Instantiates an AssemblyScript module from a response using the specified imports. */
    async function instantiateStreaming(response, imports) {
        return postInstantiate(
            preInstantiate(imports || (imports = {})),
            (await WebAssembly.instantiateStreaming(response, imports)).instance
        );
    }

    exports.instantiateStreaming = instantiateStreaming;

    /** Demangles an AssemblyScript module's exports to a friendly object structure. */
    function demangle(exports, baseModule) {
        var module = baseModule ? Object.create(baseModule) : {};
        var setargc = exports._setargc || function() {};

        function hasOwnProperty(elem, prop) {
            return Object.prototype.hasOwnProperty.call(elem, prop);
        }
        for (let internalName in exports) {
            if (!hasOwnProperty(exports, internalName)) continue;
            let elem = exports[internalName];
            let parts = internalName.split(".");
            let curr = module;
            while (parts.length > 1) {
                let part = parts.shift();
                if (!hasOwnProperty(curr, part)) curr[part] = {};
                curr = curr[part];
            }
            let name = parts[0];
            let hash = name.indexOf("#");
            if (hash >= 0) {
                let className = name.substring(0, hash);
                let classElem = curr[className];
                if (typeof classElem === "undefined" || !classElem.prototype) {
                    let ctor = function(...args) {
                        return ctor.wrap(ctor.prototype.constructor(...args));
                    };
                    ctor.prototype = {};
                    ctor.wrap = function(thisValue) {
                        return Object.create(ctor.prototype, {
                            "this": {
                                value: thisValue,
                                writable: false
                            }
                        });
                    };
                    if (classElem) Object.getOwnPropertyNames(classElem).forEach(name =>
                        Object.defineProperty(ctor, name, Object.getOwnPropertyDescriptor(classElem, name))
                    );
                    curr[className] = ctor;
                }
                name = name.substring(hash + 1);
                curr = curr[className].prototype;
                if (/^(get|set):/.test(name)) {
                    if (!hasOwnProperty(curr, name = name.substring(4))) {
                        let getter = exports[internalName.replace("set:", "get:")];
                        let setter = exports[internalName.replace("get:", "set:")];
                        Object.defineProperty(curr, name, {
                            get: function() {
                                return getter(this.this);
                            },
                            set: function(value) {
                                setter(this.this, value);
                            },
                            enumerable: true
                        });
                    }
                } else {
                    curr[name] = wrapFunction(elem, setargc);
                }
            } else {
                if (/^(get|set):/.test(name)) {
                    if (!hasOwnProperty(curr, name = name.substring(4))) {
                        Object.defineProperty(curr, name, {
                            get: exports[internalName.replace("set:", "get:")],
                            set: exports[internalName.replace("get:", "set:")],
                            enumerable: true
                        });
                    }
                } else if (typeof elem === "function") {
                    curr[name] = wrapFunction(elem, setargc);
                } else {
                    curr[name] = elem;
                }
            }
        }

        return module;
    }

    exports.demangle = demangle;

    return exports;
}());

(async() => {
    const heap_size = 65536 * 4096;
    const pages = ((heap_size + 0xffff) & ~0xffff) >>> 16;
    const imports = {
        "env": {
            memory: new WebAssembly.Memory({
                initial: pages
            })
        }
    };
    wasm = loader.instantiateBuffer(await (await fetch("optimized.wasm")).arrayBuffer(), imports);
    hide(".loading");
    login();
})();