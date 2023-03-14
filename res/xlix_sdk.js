let wasm;

const cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachedUint8Memory0 = null;

function getUint8Memory0() {
    if (cachedUint8Memory0 === null || cachedUint8Memory0.byteLength === 0) {
        cachedUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8Memory0;
}

function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}

const heap = new Array(128).fill(undefined);

heap.push(undefined, null, true, false);

let heap_next = heap.length;

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

function getObject(idx) { return heap[idx]; }

function dropObject(idx) {
    if (idx < 132) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

let cachedInt32Memory0 = null;

function getInt32Memory0() {
    if (cachedInt32Memory0 === null || cachedInt32Memory0.byteLength === 0) {
        cachedInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachedInt32Memory0;
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = new TextEncoder('utf-8');

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len);

    const mem = getUint8Memory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}
/**
* @param {string} pass
* @returns {number}
*/
export function check_password(pass) {
    const ptr0 = passStringToWasm0(pass, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.check_password(ptr0, len0);
    return ret >>> 0;
}

/**
* @param {string} login
* @returns {number}
*/
export function check_login(login) {
    const ptr0 = passStringToWasm0(login, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.check_login(ptr0, len0);
    return ret >>> 0;
}

/**
* @param {string} name
* @returns {number}
*/
export function check_folder_name(name) {
    const ptr0 = passStringToWasm0(name, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.check_folder_name(ptr0, len0);
    return ret >>> 0;
}

/**
* @param {string} keys_json
* @param {string} enc_key
* @returns {WebClientKeys}
*/
export function decrypt_response_keys(keys_json, enc_key) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        const ptr0 = passStringToWasm0(keys_json, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(enc_key, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len1 = WASM_VECTOR_LEN;
        wasm.decrypt_response_keys(retptr, ptr0, len0, ptr1, len1);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var r2 = getInt32Memory0()[retptr / 4 + 2];
        if (r2) {
            throw takeObject(r1);
        }
        return WebClientKeys.__wrap(r0);
    } finally {
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}

/**
* @param {string} salt
* @param {string} password
* @returns {SecKeys}
*/
export function compute_secret_keys(salt, password) {
    const ptr0 = passStringToWasm0(salt, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(password, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.compute_secret_keys(ptr0, len0, ptr1, len1);
    return SecKeys.__wrap(ret);
}

/**
* @param {string} login
* @param {string} password
* @returns {AccountData}
*/
export function create_account_data(login, password) {
    const ptr0 = passStringToWasm0(login, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(password, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.create_account_data(ptr0, len0, ptr1, len1);
    return AccountData.__wrap(ret);
}

/**
* @param {string} login
* @param {string} auth_key
* @returns {AuthData}
*/
export function create_auth_data(login, auth_key) {
    const ptr0 = passStringToWasm0(login, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(auth_key, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.create_auth_data(ptr0, len0, ptr1, len1);
    return AuthData.__wrap(ret);
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        wasm.__wbindgen_export_3(addHeapObject(e));
    }
}

function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
*/
export const Check = Object.freeze({ Ok:0,"0":"Ok",TooLong:1,"1":"TooLong",TooShort:2,"2":"TooShort",BadCharacter:3,"3":"BadCharacter", });
/**
*/
export class AccountData {

    static __wrap(ptr) {
        const obj = Object.create(AccountData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_accountdata_free(ptr);
    }
    /**
    * Random 128 bit value in hex
    * @returns {string}
    */
    get r_value() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_r_value(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * Random 128 bit value in hex
    * @param {string} arg0
    */
    set r_value(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_r_value(this.ptr, ptr0, len0);
    }
    /**
    * Encrypted master key (128 bit value)
    * @returns {string}
    */
    get master() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_master(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * Encrypted master key (128 bit value)
    * @param {string} arg0
    */
    set master(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_master(this.ptr, ptr0, len0);
    }
    /**
    * Encrypted RSA private key (pkcs1)
    * @returns {string}
    */
    get rsa_pv() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_rsa_pv(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * Encrypted RSA private key (pkcs1)
    * @param {string} arg0
    */
    set rsa_pv(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_rsa_pv(this.ptr, ptr0, len0);
    }
    /**
    * Raw RSA public key
    * @returns {string}
    */
    get rsa_pub() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_rsa_pub(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * Raw RSA public key
    * @param {string} arg0
    */
    set rsa_pub(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_rsa_pub(this.ptr, ptr0, len0);
    }
    /**
    * Hashed first 128 bits of the auth key
    * @returns {string}
    */
    get b128_auth_hash() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_b128_auth_hash(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * Hashed first 128 bits of the auth key
    * @param {string} arg0
    */
    set b128_auth_hash(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_b128_auth_hash(this.ptr, ptr0, len0);
    }
    /**
    * Just the login
    * @returns {string}
    */
    get login() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_login(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * Just the login
    * @param {string} arg0
    */
    set login(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_login(this.ptr, ptr0, len0);
    }
    /**
    * @returns {string}
    */
    to_json() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.accountdata_to_json(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
}
/**
*/
export class AuthData {

    static __wrap(ptr) {
        const obj = Object.create(AuthData.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_authdata_free(ptr);
    }
    /**
    * @returns {string}
    */
    get login() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_r_value(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * @param {string} arg0
    */
    set login(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_r_value(this.ptr, ptr0, len0);
    }
    /**
    * @returns {string}
    */
    get auth() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_master(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * @param {string} arg0
    */
    set auth(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_master(this.ptr, ptr0, len0);
    }
    /**
    * @returns {string}
    */
    to_json() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.authdata_to_json(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
}
/**
* Computated keys used for decryption and authentication
*/
export class SecKeys {

    static __wrap(ptr) {
        const obj = Object.create(SecKeys.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_seckeys_free(ptr);
    }
    /**
    * @returns {string}
    */
    get auth_key() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_r_value(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * @param {string} arg0
    */
    set auth_key(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_r_value(this.ptr, ptr0, len0);
    }
    /**
    * @returns {string}
    */
    get enc_key() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_master(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * @param {string} arg0
    */
    set enc_key(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_master(this.ptr, ptr0, len0);
    }
}
/**
* Same as ClientKeys but for WASM
*/
export class WebClientKeys {

    static __wrap(ptr) {
        const obj = Object.create(WebClientKeys.prototype);
        obj.ptr = ptr;

        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;

        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_webclientkeys_free(ptr);
    }
    /**
    * @returns {string}
    */
    get master() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_r_value(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * @param {string} arg0
    */
    set master(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_r_value(this.ptr, ptr0, len0);
    }
    /**
    * @returns {string}
    */
    get session() {
        try {
            const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
            wasm.__wbg_get_accountdata_master(retptr, this.ptr);
            var r0 = getInt32Memory0()[retptr / 4 + 0];
            var r1 = getInt32Memory0()[retptr / 4 + 1];
            return getStringFromWasm0(r0, r1);
        } finally {
            wasm.__wbindgen_add_to_stack_pointer(16);
            wasm.__wbindgen_export_0(r0, r1);
        }
    }
    /**
    * @param {string} arg0
    */
    set session(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_export_1, wasm.__wbindgen_export_2);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_accountdata_master(this.ptr, ptr0, len0);
    }
}

async function load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                if (module.headers.get('Content-Type') != 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function getImports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbindgen_string_new = function(arg0, arg1) {
        const ret = getStringFromWasm0(arg0, arg1);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_randomFillSync_6894564c2c334c42 = function() { return handleError(function (arg0, arg1, arg2) {
        getObject(arg0).randomFillSync(getArrayU8FromWasm0(arg1, arg2));
    }, arguments) };
    imports.wbg.__wbindgen_object_drop_ref = function(arg0) {
        takeObject(arg0);
    };
    imports.wbg.__wbg_getRandomValues_805f1c3d65988a5a = function() { return handleError(function (arg0, arg1) {
        getObject(arg0).getRandomValues(getObject(arg1));
    }, arguments) };
    imports.wbg.__wbg_crypto_e1d53a1d73fb10b8 = function(arg0) {
        const ret = getObject(arg0).crypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_object = function(arg0) {
        const val = getObject(arg0);
        const ret = typeof(val) === 'object' && val !== null;
        return ret;
    };
    imports.wbg.__wbg_process_038c26bf42b093f8 = function(arg0) {
        const ret = getObject(arg0).process;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_versions_ab37218d2f0b24a8 = function(arg0) {
        const ret = getObject(arg0).versions;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_node_080f4b19d15bc1fe = function(arg0) {
        const ret = getObject(arg0).node;
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_is_string = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'string';
        return ret;
    };
    imports.wbg.__wbg_msCrypto_6e7d3e1f92610cbb = function(arg0) {
        const ret = getObject(arg0).msCrypto;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_require_78a3dcfbdba9cbce = function() { return handleError(function () {
        const ret = module.require;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_is_function = function(arg0) {
        const ret = typeof(getObject(arg0)) === 'function';
        return ret;
    };
    imports.wbg.__wbg_newnoargs_2b8b6bd7753c76ba = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_call_95d1ea488d03e4e8 = function() { return handleError(function (arg0, arg1) {
        const ret = getObject(arg0).call(getObject(arg1));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_object_clone_ref = function(arg0) {
        const ret = getObject(arg0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_call_9495de66fdbe016b = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = getObject(arg0).call(getObject(arg1), getObject(arg2));
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_buffer_cf65c07de34b9a08 = function(arg0) {
        const ret = getObject(arg0).buffer;
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_self_e7c1f827057f6584 = function() { return handleError(function () {
        const ret = self.self;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_window_a09ec664e14b1b81 = function() { return handleError(function () {
        const ret = window.window;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_globalThis_87cbb8506fecf3a9 = function() { return handleError(function () {
        const ret = globalThis.globalThis;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbg_global_c85a9259e621f3db = function() { return handleError(function () {
        const ret = global.global;
        return addHeapObject(ret);
    }, arguments) };
    imports.wbg.__wbindgen_is_undefined = function(arg0) {
        const ret = getObject(arg0) === undefined;
        return ret;
    };
    imports.wbg.__wbg_new_537b7341ce90bb31 = function(arg0) {
        const ret = new Uint8Array(getObject(arg0));
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_set_17499e8aa4003ebd = function(arg0, arg1, arg2) {
        getObject(arg0).set(getObject(arg1), arg2 >>> 0);
    };
    imports.wbg.__wbg_length_27a2afe8ab42b09f = function(arg0) {
        const ret = getObject(arg0).length;
        return ret;
    };
    imports.wbg.__wbg_newwithlength_b56c882b57805732 = function(arg0) {
        const ret = new Uint8Array(arg0 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbg_subarray_7526649b91a252a6 = function(arg0, arg1, arg2) {
        const ret = getObject(arg0).subarray(arg1 >>> 0, arg2 >>> 0);
        return addHeapObject(ret);
    };
    imports.wbg.__wbindgen_throw = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbindgen_memory = function() {
        const ret = wasm.memory;
        return addHeapObject(ret);
    };

    return imports;
}

function initMemory(imports, maybe_memory) {

}

function finalizeInit(instance, module) {
    wasm = instance.exports;
    init.__wbindgen_wasm_module = module;
    cachedInt32Memory0 = null;
    cachedUint8Memory0 = null;


    return wasm;
}

function initSync(module) {
    const imports = getImports();

    initMemory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return finalizeInit(instance, module);
}

async function init(input) {
    if (typeof input === 'undefined') {
        input = new URL('xlix_sdk_bg.wasm', import.meta.url);
    }
    const imports = getImports();

    if (typeof input === 'string' || (typeof Request === 'function' && input instanceof Request) || (typeof URL === 'function' && input instanceof URL)) {
        input = fetch(input);
    }

    initMemory(imports);

    const { instance, module } = await load(await input, imports);

    return finalizeInit(instance, module);
}

export { initSync }
export default init;
