import * as wasm from './cardano_wallet_bg';

const heap = new Array(32);

heap.fill(undefined);

heap.push(undefined, null, true, false);

function getObject(idx) { return heap[idx]; }

let heap_next = heap.length;

function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}

function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}

function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];

    heap[idx] = obj;
    return idx;
}

let cachedTextEncoder = new TextEncoder('utf-8');

let cachegetUint8Memory = null;
function getUint8Memory() {
    if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory;
}

let WASM_VECTOR_LEN = 0;

let passStringToWasm;
if (typeof cachedTextEncoder.encodeInto === 'function') {
    passStringToWasm = function(arg) {

        let size = arg.length;
        let ptr = wasm.__wbindgen_malloc(size);
        let writeOffset = 0;
        while (true) {
            const view = getUint8Memory().subarray(ptr + writeOffset, ptr + size);
            const { read, written } = cachedTextEncoder.encodeInto(arg, view);
            arg = arg.substring(read);
            writeOffset += written;
            if (arg.length === 0) {
                break;
            }
            ptr = wasm.__wbindgen_realloc(ptr, size, size * 2);
            size *= 2;
        }
        WASM_VECTOR_LEN = writeOffset;
        return ptr;
    };
} else {
    passStringToWasm = function(arg) {

        const buf = cachedTextEncoder.encode(arg);
        const ptr = wasm.__wbindgen_malloc(buf.length);
        getUint8Memory().set(buf, ptr);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    };
}

let cachedTextDecoder = new TextDecoder('utf-8');

function getStringFromWasm(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
}

let cachedGlobalArgumentPtr = null;
function globalArgumentPtr() {
    if (cachedGlobalArgumentPtr === null) {
        cachedGlobalArgumentPtr = wasm.__wbindgen_global_argument_ptr();
    }
    return cachedGlobalArgumentPtr;
}

let cachegetUint32Memory = null;
function getUint32Memory() {
    if (cachegetUint32Memory === null || cachegetUint32Memory.buffer !== wasm.memory.buffer) {
        cachegetUint32Memory = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory;
}

function passArray8ToWasm(arg) {
    const ptr = wasm.__wbindgen_malloc(arg.length * 1);
    getUint8Memory().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
* @param {Entropy} entropy
* @param {Uint8Array} iv
* @param {string} password
* @returns {any}
*/
export function paper_wallet_scramble(entropy, iv, password) {
    const ptr1 = passArray8ToWasm(iv);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm(password);
    const len2 = WASM_VECTOR_LEN;
    try {
        return takeObject(wasm.paper_wallet_scramble(entropy.ptr, ptr1, len1, ptr2, len2));

    } finally {
        wasm.__wbindgen_free(ptr1, len1 * 1);
        wasm.__wbindgen_free(ptr2, len2 * 1);

    }

}

/**
* @param {Uint8Array} paper
* @param {string} password
* @returns {Entropy}
*/
export function paper_wallet_unscramble(paper, password) {
    const ptr0 = passArray8ToWasm(paper);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm(password);
    const len1 = WASM_VECTOR_LEN;
    try {
        return Entropy.__wrap(wasm.paper_wallet_unscramble(ptr0, len0, ptr1, len1));

    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

/**
* encrypt the given data with a password, a salt and a nonce
*
* Salt: must be 32 bytes long;
* Nonce: must be 12 bytes long;
*
* @param {string} password
* @param {Uint8Array} salt
* @param {Uint8Array} nonce
* @param {Uint8Array} data
* @returns {any}
*/
export function password_encrypt(password, salt, nonce, data) {
    const ptr0 = passStringToWasm(password);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm(salt);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm(nonce);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm(data);
    const len3 = WASM_VECTOR_LEN;
    try {
        return takeObject(wasm.password_encrypt(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3));

    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);
        wasm.__wbindgen_free(ptr2, len2 * 1);
        wasm.__wbindgen_free(ptr3, len3 * 1);

    }

}

/**
* decrypt the data with the password
*
* @param {string} password
* @param {Uint8Array} encrypted_data
* @returns {any}
*/
export function password_decrypt(password, encrypted_data) {
    const ptr0 = passStringToWasm(password);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm(encrypted_data);
    const len1 = WASM_VECTOR_LEN;
    try {
        return takeObject(wasm.password_decrypt(ptr0, len0, ptr1, len1));

    } finally {
        wasm.__wbindgen_free(ptr0, len0 * 1);
        wasm.__wbindgen_free(ptr1, len1 * 1);

    }

}

export function __wbindgen_string_new(p, l) { return addHeapObject(getStringFromWasm(p, l)); }

export function __wbindgen_json_parse(ptr, len) { return addHeapObject(JSON.parse(getStringFromWasm(ptr, len))); }

export function __wbindgen_json_serialize(idx, ptrptr) {
    const ptr = passStringToWasm(JSON.stringify(getObject(idx)));
    getUint32Memory()[ptrptr / 4] = ptr;
    return WASM_VECTOR_LEN;
}

export function __wbindgen_rethrow(idx) { throw takeObject(idx); }

export function __wbindgen_throw(ptr, len) {
    throw new Error(getStringFromWasm(ptr, len));
}

function freeAccountIndex(ptr) {

    wasm.__wbg_accountindex_free(ptr);
}
/**
*/
export class AccountIndex {

    static __wrap(ptr) {
        const obj = Object.create(AccountIndex.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeAccountIndex(ptr);
    }

    /**
    * @param {number} index
    * @returns {AccountIndex}
    */
    static new(index) {
        return AccountIndex.__wrap(wasm.accountindex_new(index));
    }
}

function freeAddress(ptr) {

    wasm.__wbg_address_free(ptr);
}
/**
*/
export class Address {

    static __wrap(ptr) {
        const obj = Object.create(Address.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeAddress(ptr);
    }

    /**
    * @returns {string}
    */
    to_base58() {
        const retptr = globalArgumentPtr();
        wasm.address_to_base58(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @param {string} s
    * @returns {Address}
    */
    static from_base58(s) {
        const ptr0 = passStringToWasm(s);
        const len0 = WASM_VECTOR_LEN;
        try {
            return Address.__wrap(wasm.address_from_base58(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
}

function freeAddressKeyIndex(ptr) {

    wasm.__wbg_addresskeyindex_free(ptr);
}
/**
*/
export class AddressKeyIndex {

    static __wrap(ptr) {
        const obj = Object.create(AddressKeyIndex.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeAddressKeyIndex(ptr);
    }

    /**
    * @param {number} index
    * @returns {AddressKeyIndex}
    */
    static new(index) {
        return AddressKeyIndex.__wrap(wasm.addresskeyindex_new(index));
    }
}

function freeBip44AccountPrivate(ptr) {

    wasm.__wbg_bip44accountprivate_free(ptr);
}
/**
*/
export class Bip44AccountPrivate {

    static __wrap(ptr) {
        const obj = Object.create(Bip44AccountPrivate.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeBip44AccountPrivate(ptr);
    }

    /**
    * @param {PrivateKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44AccountPrivate}
    */
    static new(key, derivation_scheme) {
        const ptr0 = key.ptr;
        key.ptr = 0;
        const ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        return Bip44AccountPrivate.__wrap(wasm.bip44accountprivate_new(ptr0, ptr1));
    }
    /**
    * @returns {Bip44AccountPublic}
    */
    public() {
        return Bip44AccountPublic.__wrap(wasm.bip44accountprivate_public(this.ptr));
    }
    /**
    * @param {boolean} internal
    * @param {AddressKeyIndex} index
    * @returns {PrivateKey}
    */
    address_key(internal, index) {
        const ptr1 = index.ptr;
        index.ptr = 0;
        return PrivateKey.__wrap(wasm.bip44accountprivate_address_key(this.ptr, internal, ptr1));
    }
    /**
    * @returns {PrivateKey}
    */
    key() {
        return PrivateKey.__wrap(wasm.bip44accountprivate_key(this.ptr));
    }
}

function freeBip44AccountPublic(ptr) {

    wasm.__wbg_bip44accountpublic_free(ptr);
}
/**
*/
export class Bip44AccountPublic {

    static __wrap(ptr) {
        const obj = Object.create(Bip44AccountPublic.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeBip44AccountPublic(ptr);
    }

    /**
    * @param {PublicKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44AccountPublic}
    */
    static new(key, derivation_scheme) {
        const ptr0 = key.ptr;
        key.ptr = 0;
        const ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        return Bip44AccountPublic.__wrap(wasm.bip44accountpublic_new(ptr0, ptr1));
    }
    /**
    * @param {boolean} internal
    * @param {AddressKeyIndex} index
    * @returns {PublicKey}
    */
    address_key(internal, index) {
        const ptr1 = index.ptr;
        index.ptr = 0;
        return PublicKey.__wrap(wasm.bip44accountpublic_address_key(this.ptr, internal, ptr1));
    }
    /**
    * @returns {PublicKey}
    */
    key() {
        return PublicKey.__wrap(wasm.bip44accountpublic_key(this.ptr));
    }
}

function freeBip44RootPrivateKey(ptr) {

    wasm.__wbg_bip44rootprivatekey_free(ptr);
}
/**
* Root Private Key of a BIP44 HD Wallet
*/
export class Bip44RootPrivateKey {

    static __wrap(ptr) {
        const obj = Object.create(Bip44RootPrivateKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeBip44RootPrivateKey(ptr);
    }

    /**
    * @param {PrivateKey} key
    * @param {DerivationScheme} derivation_scheme
    * @returns {Bip44RootPrivateKey}
    */
    static new(key, derivation_scheme) {
        const ptr0 = key.ptr;
        key.ptr = 0;
        const ptr1 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        return Bip44RootPrivateKey.__wrap(wasm.bip44rootprivatekey_new(ptr0, ptr1));
    }
    /**
    * recover a wallet from the given mnemonic words and the given password
    *
    * To recover an icarus wallet:
    * * 15 mnemonic words;
    * * empty password;
    *
    * @param {Entropy} entropy
    * @param {string} password
    * @returns {Bip44RootPrivateKey}
    */
    static recover(entropy, password) {
        const ptr1 = passStringToWasm(password);
        const len1 = WASM_VECTOR_LEN;
        try {
            return Bip44RootPrivateKey.__wrap(wasm.bip44rootprivatekey_recover(entropy.ptr, ptr1, len1));

        } finally {
            wasm.__wbindgen_free(ptr1, len1 * 1);

        }

    }
    /**
    * @param {AccountIndex} index
    * @returns {Bip44AccountPrivate}
    */
    bip44_account(index) {
        const ptr0 = index.ptr;
        index.ptr = 0;
        return Bip44AccountPrivate.__wrap(wasm.bip44rootprivatekey_bip44_account(this.ptr, ptr0));
    }
    /**
    * @returns {PrivateKey}
    */
    key() {
        return PrivateKey.__wrap(wasm.bip44rootprivatekey_key(this.ptr));
    }
}

function freeBlockchainSettings(ptr) {

    wasm.__wbg_blockchainsettings_free(ptr);
}
/**
* setting of the blockchain
*
* This includes the `ProtocolMagic` a discriminant value to differentiate
* different instances of the cardano blockchain (Mainnet, Testnet... ).
*/
export class BlockchainSettings {

    static __wrap(ptr) {
        const obj = Object.create(BlockchainSettings.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeBlockchainSettings(ptr);
    }

    /**
    * serialize into a JsValue object. Allowing the client to store the settings
    * or see changes in the settings or change the settings.
    *
    * Note that this is not recommended to change the settings on the fly. Doing
    * so you might not be able to recover your funds anymore or to send new
    * transactions.
    * @returns {any}
    */
    to_json() {
        return takeObject(wasm.blockchainsettings_to_json(this.ptr));
    }
    /**
    * retrieve the object from a JsValue.
    * @param {any} value
    * @returns {BlockchainSettings}
    */
    static from_json(value) {
        return BlockchainSettings.__wrap(wasm.blockchainsettings_from_json(addHeapObject(value)));
    }
    /**
    * default settings to work with Cardano Mainnet
    * @returns {BlockchainSettings}
    */
    static mainnet() {
        return BlockchainSettings.__wrap(wasm.blockchainsettings_mainnet());
    }
}

function freeCoin(ptr) {

    wasm.__wbg_coin_free(ptr);
}
/**
*/
export class Coin {

    static __wrap(ptr) {
        const obj = Object.create(Coin.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeCoin(ptr);
    }

    /**
    * @returns {}
    */
    constructor() {
        this.ptr = wasm.coin_new();
    }
    /**
    * @param {string} s
    * @returns {Coin}
    */
    static from_str(s) {
        const ptr0 = passStringToWasm(s);
        const len0 = WASM_VECTOR_LEN;
        try {
            return Coin.__wrap(wasm.coin_from_str(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    to_str() {
        const retptr = globalArgumentPtr();
        wasm.coin_to_str(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @param {number} ada
    * @param {number} lovelace
    * @returns {Coin}
    */
    static from(ada, lovelace) {
        return Coin.__wrap(wasm.coin_from(ada, lovelace));
    }
    /**
    * @returns {number}
    */
    ada() {
        return wasm.coin_ada(this.ptr);
    }
    /**
    * @returns {number}
    */
    lovelace() {
        return wasm.coin_lovelace(this.ptr);
    }
    /**
    * @param {Coin} other
    * @returns {Coin}
    */
    add(other) {
        return Coin.__wrap(wasm.coin_add(this.ptr, other.ptr));
    }
}

function freeCoinDiff(ptr) {

    wasm.__wbg_coindiff_free(ptr);
}
/**
*/
export class CoinDiff {

    static __wrap(ptr) {
        const obj = Object.create(CoinDiff.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeCoinDiff(ptr);
    }

    /**
    * @returns {boolean}
    */
    is_zero() {
        return (wasm.coindiff_is_zero(this.ptr)) !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_negative() {
        return (wasm.coindiff_is_negative(this.ptr)) !== 0;
    }
    /**
    * @returns {boolean}
    */
    is_positive() {
        return (wasm.coindiff_is_positive(this.ptr)) !== 0;
    }
    /**
    * @returns {Coin}
    */
    value() {
        return Coin.__wrap(wasm.coindiff_value(this.ptr));
    }
}

function freeDaedalusAddressChecker(ptr) {

    wasm.__wbg_daedalusaddresschecker_free(ptr);
}
/**
*/
export class DaedalusAddressChecker {

    static __wrap(ptr) {
        const obj = Object.create(DaedalusAddressChecker.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeDaedalusAddressChecker(ptr);
    }

    /**
    * create a new address checker for the given daedalus address
    * @param {DaedalusWallet} wallet
    * @returns {DaedalusAddressChecker}
    */
    static new(wallet) {
        return DaedalusAddressChecker.__wrap(wasm.daedalusaddresschecker_new(wallet.ptr));
    }
    /**
    * check that we own the given address.
    *
    * This is only possible like this because some payload is embedded in the
    * address that only our wallet can decode. Once decoded we can retrieve
    * the associated private key.
    *
    * The return private key is the key needed to sign the transaction to unlock
    * UTxO associated to the address.
    * @param {Address} address
    * @returns {DaedalusCheckedAddress}
    */
    check_address(address) {
        return DaedalusCheckedAddress.__wrap(wasm.daedalusaddresschecker_check_address(this.ptr, address.ptr));
    }
}

function freeDaedalusCheckedAddress(ptr) {

    wasm.__wbg_daedaluscheckedaddress_free(ptr);
}
/**
* result value of the check_address function of the DaedalusAddressChecker.
*
* If the address passed to check_address was recognised by the daedalus wallet
* then this object will contain the private key associated to this wallet
* private key necessary to sign transactions
*/
export class DaedalusCheckedAddress {

    static __wrap(ptr) {
        const obj = Object.create(DaedalusCheckedAddress.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeDaedalusCheckedAddress(ptr);
    }

    /**
    * return if the value contains the private key (i.e. the check_address
    * recognised an address).
    * @returns {boolean}
    */
    is_checked() {
        return (wasm.daedaluscheckedaddress_is_checked(this.ptr)) !== 0;
    }
    /**
    * @returns {PrivateKey}
    */
    private_key() {
        return PrivateKey.__wrap(wasm.daedaluscheckedaddress_private_key(this.ptr));
    }
}

function freeDaedalusWallet(ptr) {

    wasm.__wbg_daedaluswallet_free(ptr);
}
/**
*/
export class DaedalusWallet {

    static __wrap(ptr) {
        const obj = Object.create(DaedalusWallet.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeDaedalusWallet(ptr);
    }

    /**
    * @param {PrivateKey} key
    * @returns {DaedalusWallet}
    */
    static new(key) {
        const ptr0 = key.ptr;
        key.ptr = 0;
        return DaedalusWallet.__wrap(wasm.daedaluswallet_new(ptr0));
    }
    /**
    * @param {Entropy} entropy
    * @returns {DaedalusWallet}
    */
    static recover(entropy) {
        return DaedalusWallet.__wrap(wasm.daedaluswallet_recover(entropy.ptr));
    }
}

function freeDerivationScheme(ptr) {

    wasm.__wbg_derivationscheme_free(ptr);
}
/**
* There is a special function to use when deriving Addresses. This function
* has been revised to offer stronger properties. This is why there is a
* V2 derivation scheme. The V1 being the legacy one still used in daedalus
* now a days.
*
* It is strongly advised to use V2 as the V1 is deprecated since April 2018.
* Its support is already provided for backward compatibility with old
* addresses.
*/
export class DerivationScheme {

    static __wrap(ptr) {
        const obj = Object.create(DerivationScheme.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeDerivationScheme(ptr);
    }

    /**
    * deprecated, provided here only for backward compatibility with
    * Daedalus\' addresses
    * @returns {DerivationScheme}
    */
    static v1() {
        return DerivationScheme.__wrap(wasm.derivationscheme_v1());
    }
    /**
    * the recommended settings
    * @returns {DerivationScheme}
    */
    static v2() {
        return DerivationScheme.__wrap(wasm.derivationscheme_v2());
    }
}

function freeEntropy(ptr) {

    wasm.__wbg_entropy_free(ptr);
}
/**
* the entropy associated to mnemonics. This is a bytes representation of the
* mnemonics the user has to remember how to generate the root key of an
* HD Wallet.
*
* TODO: interface to generate a new entropy
*
* # Security considerations
*
* * do not store this value without encrypting it;
* * do not leak the mnemonics;
* * make sure the user remembers the mnemonics string;
*
*/
export class Entropy {

    static __wrap(ptr) {
        const obj = Object.create(Entropy.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeEntropy(ptr);
    }

    /**
    * retrieve the initial entropy of a wallet from the given
    * english mnemonics.
    * @param {string} mnemonics
    * @returns {Entropy}
    */
    static from_english_mnemonics(mnemonics) {
        const ptr0 = passStringToWasm(mnemonics);
        const len0 = WASM_VECTOR_LEN;
        try {
            return Entropy.__wrap(wasm.entropy_from_english_mnemonics(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    to_english_mnemonics() {
        const retptr = globalArgumentPtr();
        wasm.entropy_to_english_mnemonics(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @returns {any}
    */
    to_array() {
        return takeObject(wasm.entropy_to_array(this.ptr));
    }
}

function freeInputSelectionBuilder(ptr) {

    wasm.__wbg_inputselectionbuilder_free(ptr);
}
/**
*/
export class InputSelectionBuilder {

    static __wrap(ptr) {
        const obj = Object.create(InputSelectionBuilder.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeInputSelectionBuilder(ptr);
    }

    /**
    * @returns {InputSelectionBuilder}
    */
    static first_match_first() {
        return InputSelectionBuilder.__wrap(wasm.inputselectionbuilder_first_match_first());
    }
    /**
    * @returns {InputSelectionBuilder}
    */
    static largest_first() {
        return InputSelectionBuilder.__wrap(wasm.inputselectionbuilder_largest_first());
    }
    /**
    * @param {Coin} dust_threshold
    * @returns {InputSelectionBuilder}
    */
    static blackjack(dust_threshold) {
        const ptr0 = dust_threshold.ptr;
        dust_threshold.ptr = 0;
        return InputSelectionBuilder.__wrap(wasm.inputselectionbuilder_blackjack(ptr0));
    }
    /**
    * @param {TxInput} tx_input
    * @returns {void}
    */
    add_input(tx_input) {
        return wasm.inputselectionbuilder_add_input(this.ptr, tx_input.ptr);
    }
    /**
    * @param {TxOut} output
    * @returns {void}
    */
    add_output(output) {
        return wasm.inputselectionbuilder_add_output(this.ptr, output.ptr);
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @param {OutputPolicy} output_policy
    * @returns {InputSelectionResult}
    */
    select_inputs(fee_algorithm, output_policy) {
        return InputSelectionResult.__wrap(wasm.inputselectionbuilder_select_inputs(this.ptr, fee_algorithm.ptr, output_policy.ptr));
    }
}

function freeInputSelectionResult(ptr) {

    wasm.__wbg_inputselectionresult_free(ptr);
}
/**
*/
export class InputSelectionResult {

    static __wrap(ptr) {
        const obj = Object.create(InputSelectionResult.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeInputSelectionResult(ptr);
    }

    /**
    * @param {TxoPointer} txo_pointer
    * @returns {boolean}
    */
    is_input(txo_pointer) {
        return (wasm.inputselectionresult_is_input(this.ptr, txo_pointer.ptr)) !== 0;
    }
    /**
    * @returns {Coin}
    */
    estimated_fees() {
        return Coin.__wrap(wasm.inputselectionresult_estimated_fees(this.ptr));
    }
    /**
    * @returns {Coin}
    */
    estimated_change() {
        return Coin.__wrap(wasm.inputselectionresult_estimated_change(this.ptr));
    }
}

function freeLinearFeeAlgorithm(ptr) {

    wasm.__wbg_linearfeealgorithm_free(ptr);
}
/**
* This is the linear fee algorithm used buy the current cardano blockchain.
*
* However it is possible the linear fee algorithm may change its settings:
*
* It is currently a function `fee(n) = a * x + b`. `a` and `b` can be
* re-configured by a protocol update. Users of this object need to be aware
* that it may change and that they might need to update its settings.
*
*/
export class LinearFeeAlgorithm {

    static __wrap(ptr) {
        const obj = Object.create(LinearFeeAlgorithm.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeLinearFeeAlgorithm(ptr);
    }

    /**
    * this is the default mainnet linear fee algorithm. It is also known to work
    * with the staging network and the current testnet.
    *
    * @returns {LinearFeeAlgorithm}
    */
    static default() {
        return LinearFeeAlgorithm.__wrap(wasm.linearfeealgorithm_default());
    }
}

function freeOutputPolicy(ptr) {

    wasm.__wbg_outputpolicy_free(ptr);
}
/**
* This is the Output policy for automatic Input selection.
*/
export class OutputPolicy {

    static __wrap(ptr) {
        const obj = Object.create(OutputPolicy.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeOutputPolicy(ptr);
    }

    /**
    * requires to send back all the spare changes to only one given address
    * @param {Address} address
    * @returns {OutputPolicy}
    */
    static change_to_one_address(address) {
        const ptr0 = address.ptr;
        address.ptr = 0;
        return OutputPolicy.__wrap(wasm.outputpolicy_change_to_one_address(ptr0));
    }
}

function freePrivateKey(ptr) {

    wasm.__wbg_privatekey_free(ptr);
}
/**
* A given private key. You can use this key to sign transactions.
*
* # security considerations
*
* * do not store this key without encrypting it;
* * if leaked anyone can _spend_ a UTxO (Unspent Transaction Output)
*   with it;
*
*/
export class PrivateKey {

    static __wrap(ptr) {
        const obj = Object.create(PrivateKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freePrivateKey(ptr);
    }

    /**
    * create a new private key from a given Entropy
    * @param {Entropy} entropy
    * @param {string} password
    * @returns {PrivateKey}
    */
    static new(entropy, password) {
        const ptr1 = passStringToWasm(password);
        const len1 = WASM_VECTOR_LEN;
        try {
            return PrivateKey.__wrap(wasm.privatekey_new(entropy.ptr, ptr1, len1));

        } finally {
            wasm.__wbindgen_free(ptr1, len1 * 1);

        }

    }
    /**
    * retrieve a private key from the given hexadecimal string
    * @param {string} hex
    * @returns {PrivateKey}
    */
    static from_hex(hex) {
        const ptr0 = passStringToWasm(hex);
        const len0 = WASM_VECTOR_LEN;
        try {
            return PrivateKey.__wrap(wasm.privatekey_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * convert the private key to an hexadecimal string
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.privatekey_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * get the public key associated to this private key
    * @returns {PublicKey}
    */
    public() {
        return PublicKey.__wrap(wasm.privatekey_public(this.ptr));
    }
    /**
    * sign some bytes with this private key
    * @param {Uint8Array} data
    * @returns {Signature}
    */
    sign(data) {
        const ptr0 = passArray8ToWasm(data);
        const len0 = WASM_VECTOR_LEN;
        try {
            return Signature.__wrap(wasm.privatekey_sign(this.ptr, ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * derive this private key with the given index.
    *
    * # Security considerations
    *
    * * prefer the use of DerivationScheme::v2 when possible;
    * * hard derivation index cannot be soft derived with the public key
    *
    * # Hard derivation vs Soft derivation
    *
    * If you pass an index below 0x80000000 then it is a soft derivation.
    * The advantage of soft derivation is that it is possible to derive the
    * public key too. I.e. derivation the private key with a soft derivation
    * index and then retrieving the associated public key is equivalent to
    * deriving the public key associated to the parent private key.
    *
    * Hard derivation index does not allow public key derivation.
    *
    * This is why deriving the private key should not fail while deriving
    * the public key may fail (if the derivation index is invalid).
    *
    * @param {DerivationScheme} derivation_scheme
    * @param {number} index
    * @returns {PrivateKey}
    */
    derive(derivation_scheme, index) {
        const ptr0 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        return PrivateKey.__wrap(wasm.privatekey_derive(this.ptr, ptr0, index));
    }
}

function freePrivateRedeemKey(ptr) {

    wasm.__wbg_privateredeemkey_free(ptr);
}
/**
*/
export class PrivateRedeemKey {

    static __wrap(ptr) {
        const obj = Object.create(PrivateRedeemKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freePrivateRedeemKey(ptr);
    }

    /**
    * retrieve the private redeeming key from the given bytes (expect 64 bytes)
    * @param {Uint8Array} bytes
    * @returns {PrivateRedeemKey}
    */
    static from_bytes(bytes) {
        const ptr0 = passArray8ToWasm(bytes);
        const len0 = WASM_VECTOR_LEN;
        try {
            return PrivateRedeemKey.__wrap(wasm.privateredeemkey_from_bytes(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * retrieve a private key from the given hexadecimal string
    * @param {string} hex
    * @returns {PrivateRedeemKey}
    */
    static from_hex(hex) {
        const ptr0 = passStringToWasm(hex);
        const len0 = WASM_VECTOR_LEN;
        try {
            return PrivateRedeemKey.__wrap(wasm.privateredeemkey_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * convert the private key to an hexadecimal string
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.privateredeemkey_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * get the public key associated to this private key
    * @returns {PublicRedeemKey}
    */
    public() {
        return PublicRedeemKey.__wrap(wasm.privateredeemkey_public(this.ptr));
    }
    /**
    * sign some bytes with this private key
    * @param {Uint8Array} data
    * @returns {RedeemSignature}
    */
    sign(data) {
        const ptr0 = passArray8ToWasm(data);
        const len0 = WASM_VECTOR_LEN;
        try {
            return RedeemSignature.__wrap(wasm.privateredeemkey_sign(this.ptr, ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
}

function freePublicKey(ptr) {

    wasm.__wbg_publickey_free(ptr);
}
/**
* The public key associated to a given private key.
*
* It is not possible to sign (and then spend) with a private key.
* However it is possible to verify a Signature.
*
* # Security Consideration
*
* * it is rather harmless to leak a public key, in the worst case
*   only the privacy is leaked;
*
*/
export class PublicKey {

    static __wrap(ptr) {
        const obj = Object.create(PublicKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freePublicKey(ptr);
    }

    /**
    * @param {string} hex
    * @returns {PublicKey}
    */
    static from_hex(hex) {
        const ptr0 = passStringToWasm(hex);
        const len0 = WASM_VECTOR_LEN;
        try {
            return PublicKey.__wrap(wasm.publickey_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.publickey_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @param {Uint8Array} data
    * @param {Signature} signature
    * @returns {boolean}
    */
    verify(data, signature) {
        const ptr0 = passArray8ToWasm(data);
        const len0 = WASM_VECTOR_LEN;
        try {
            return (wasm.publickey_verify(this.ptr, ptr0, len0, signature.ptr)) !== 0;

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * derive this public key with the given index.
    *
    * # Errors
    *
    * If the index is not a soft derivation index (< 0x80000000) then
    * calling this method will fail.
    *
    * # Security considerations
    *
    * * prefer the use of DerivationScheme::v2 when possible;
    * * hard derivation index cannot be soft derived with the public key
    *
    * # Hard derivation vs Soft derivation
    *
    * If you pass an index below 0x80000000 then it is a soft derivation.
    * The advantage of soft derivation is that it is possible to derive the
    * public key too. I.e. derivation the private key with a soft derivation
    * index and then retrieving the associated public key is equivalent to
    * deriving the public key associated to the parent private key.
    *
    * Hard derivation index does not allow public key derivation.
    *
    * This is why deriving the private key should not fail while deriving
    * the public key may fail (if the derivation index is invalid).
    *
    * @param {DerivationScheme} derivation_scheme
    * @param {number} index
    * @returns {PublicKey}
    */
    derive(derivation_scheme, index) {
        const ptr0 = derivation_scheme.ptr;
        derivation_scheme.ptr = 0;
        return PublicKey.__wrap(wasm.publickey_derive(this.ptr, ptr0, index));
    }
    /**
    * get the bootstrap era address. I.E. this is an address without
    * stake delegation.
    * @param {BlockchainSettings} blockchain_settings
    * @returns {Address}
    */
    bootstrap_era_address(blockchain_settings) {
        return Address.__wrap(wasm.publickey_bootstrap_era_address(this.ptr, blockchain_settings.ptr));
    }
}

function freePublicRedeemKey(ptr) {

    wasm.__wbg_publicredeemkey_free(ptr);
}
/**
*/
export class PublicRedeemKey {

    static __wrap(ptr) {
        const obj = Object.create(PublicRedeemKey.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freePublicRedeemKey(ptr);
    }

    /**
    * retrieve a public key from the given hexadecimal string
    * @param {string} hex
    * @returns {PublicRedeemKey}
    */
    static from_hex(hex) {
        const ptr0 = passStringToWasm(hex);
        const len0 = WASM_VECTOR_LEN;
        try {
            return PublicRedeemKey.__wrap(wasm.publicredeemkey_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * convert the public key to an hexadecimal string
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.publicredeemkey_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * verify the signature with the given public key
    * @param {Uint8Array} data
    * @param {RedeemSignature} signature
    * @returns {boolean}
    */
    verify(data, signature) {
        const ptr0 = passArray8ToWasm(data);
        const len0 = WASM_VECTOR_LEN;
        try {
            return (wasm.publicredeemkey_verify(this.ptr, ptr0, len0, signature.ptr)) !== 0;

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * generate the address for this redeeming key
    * @param {BlockchainSettings} settings
    * @returns {Address}
    */
    address(settings) {
        return Address.__wrap(wasm.publicredeemkey_address(this.ptr, settings.ptr));
    }
}

function freeRedeemSignature(ptr) {

    wasm.__wbg_redeemsignature_free(ptr);
}
/**
*/
export class RedeemSignature {

    static __wrap(ptr) {
        const obj = Object.create(RedeemSignature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeRedeemSignature(ptr);
    }

    /**
    * @param {string} hex
    * @returns {RedeemSignature}
    */
    static from_hex(hex) {
        const ptr0 = passStringToWasm(hex);
        const len0 = WASM_VECTOR_LEN;
        try {
            return RedeemSignature.__wrap(wasm.redeemsignature_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.redeemsignature_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

function freeSignature(ptr) {

    wasm.__wbg_signature_free(ptr);
}
/**
*/
export class Signature {

    static __wrap(ptr) {
        const obj = Object.create(Signature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeSignature(ptr);
    }

    /**
    * @param {string} hex
    * @returns {Signature}
    */
    static from_hex(hex) {
        const ptr0 = passStringToWasm(hex);
        const len0 = WASM_VECTOR_LEN;
        try {
            return Signature.__wrap(wasm.signature_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.signature_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

function freeSignedTransaction(ptr) {

    wasm.__wbg_signedtransaction_free(ptr);
}
/**
* a signed transaction, ready to be sent to the network.
*/
export class SignedTransaction {

    static __wrap(ptr) {
        const obj = Object.create(SignedTransaction.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeSignedTransaction(ptr);
    }

    /**
    * @returns {string}
    */
    id() {
        const retptr = globalArgumentPtr();
        wasm.signedtransaction_id(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @returns {any}
    */
    to_json() {
        return takeObject(wasm.signedtransaction_to_json(this.ptr));
    }
    /**
    * @param {Uint8Array} bytes
    * @returns {SignedTransaction}
    */
    static from_bytes(bytes) {
        const ptr0 = passArray8ToWasm(bytes);
        const len0 = WASM_VECTOR_LEN;
        try {
            return SignedTransaction.__wrap(wasm.signedtransaction_from_bytes(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.signedtransaction_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

function freeTransaction(ptr) {

    wasm.__wbg_transaction_free(ptr);
}
/**
* a transaction type, this is not ready for sending to the network. It is only an
* intermediate type to use between the transaction builder and the transaction
* finalizer. It allows separation of concerns:
*
* 1. build the transaction on one side/thread/machine/...;
* 2. sign the transaction on the other/thread/machines/cold-wallet...;
*
*/
export class Transaction {

    static __wrap(ptr) {
        const obj = Object.create(Transaction.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTransaction(ptr);
    }

    /**
    * @returns {TransactionId}
    */
    id() {
        return TransactionId.__wrap(wasm.transaction_id(this.ptr));
    }
    /**
    * @returns {any}
    */
    to_json() {
        return takeObject(wasm.transaction_to_json(this.ptr));
    }
    /**
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.transaction_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

function freeTransactionBuilder(ptr) {

    wasm.__wbg_transactionbuilder_free(ptr);
}
/**
* The transaction builder provides a set of tools to help build
* a valid Transaction.
*/
export class TransactionBuilder {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTransactionBuilder(ptr);
    }

    /**
    * create a new transaction builder
    * @returns {}
    */
    constructor() {
        this.ptr = wasm.transactionbuilder_new();
    }
    /**
    * @param {TxoPointer} txo_pointer
    * @param {Coin} value
    * @returns {void}
    */
    add_input(txo_pointer, value) {
        const ptr1 = value.ptr;
        value.ptr = 0;
        return wasm.transactionbuilder_add_input(this.ptr, txo_pointer.ptr, ptr1);
    }
    /**
    * @returns {Coin}
    */
    get_input_total() {
        return Coin.__wrap(wasm.transactionbuilder_get_input_total(this.ptr));
    }
    /**
    * @param {TxOut} output
    * @returns {void}
    */
    add_output(output) {
        return wasm.transactionbuilder_add_output(this.ptr, output.ptr);
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @param {OutputPolicy} policy
    * @returns {any}
    */
    apply_output_policy(fee_algorithm, policy) {
        return takeObject(wasm.transactionbuilder_apply_output_policy(this.ptr, fee_algorithm.ptr, policy.ptr));
    }
    /**
    * @returns {Coin}
    */
    get_output_total() {
        return Coin.__wrap(wasm.transactionbuilder_get_output_total(this.ptr));
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @returns {Coin}
    */
    estimate_fee(fee_algorithm) {
        return Coin.__wrap(wasm.transactionbuilder_estimate_fee(this.ptr, fee_algorithm.ptr));
    }
    /**
    * @param {LinearFeeAlgorithm} fee_algorithm
    * @returns {CoinDiff}
    */
    get_balance(fee_algorithm) {
        return CoinDiff.__wrap(wasm.transactionbuilder_get_balance(this.ptr, fee_algorithm.ptr));
    }
    /**
    * @returns {CoinDiff}
    */
    get_balance_without_fees() {
        return CoinDiff.__wrap(wasm.transactionbuilder_get_balance_without_fees(this.ptr));
    }
    /**
    * @returns {Transaction}
    */
    make_transaction() {
        const ptr = this.ptr;
        this.ptr = 0;
        return Transaction.__wrap(wasm.transactionbuilder_make_transaction(ptr));
    }
}

function freeTransactionFinalized(ptr) {

    wasm.__wbg_transactionfinalized_free(ptr);
}
/**
*/
export class TransactionFinalized {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTransactionFinalized(ptr);
    }

    /**
    * @param {Transaction} transaction
    * @returns {}
    */
    constructor(transaction) {
        const ptr0 = transaction.ptr;
        transaction.ptr = 0;
        this.ptr = wasm.transactionfinalized_new(ptr0);
    }
    /**
    * @returns {TransactionId}
    */
    id() {
        return TransactionId.__wrap(wasm.transactionfinalized_id(this.ptr));
    }
    /**
    * sign the inputs of the transaction (i.e. unlock the funds the input are
    * referring to).
    *
    * The signature must be added one by one in the same order the inputs have
    * been added.
    *
    * Deprecated: use `add_witness` instead.
    * @param {BlockchainSettings} blockchain_settings
    * @param {PrivateKey} key
    * @returns {void}
    */
    sign(blockchain_settings, key) {
        return wasm.transactionfinalized_sign(this.ptr, blockchain_settings.ptr, key.ptr);
    }
    /**
    * @param {Witness} witness
    * @returns {void}
    */
    add_witness(witness) {
        const ptr0 = witness.ptr;
        witness.ptr = 0;
        return wasm.transactionfinalized_add_witness(this.ptr, ptr0);
    }
    /**
    * @returns {SignedTransaction}
    */
    finalize() {
        const ptr = this.ptr;
        this.ptr = 0;
        return SignedTransaction.__wrap(wasm.transactionfinalized_finalize(ptr));
    }
}

function freeTransactionId(ptr) {

    wasm.__wbg_transactionid_free(ptr);
}
/**
*/
export class TransactionId {

    static __wrap(ptr) {
        const obj = Object.create(TransactionId.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTransactionId(ptr);
    }

    /**
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.transactionid_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @param {string} s
    * @returns {TransactionId}
    */
    static from_hex(s) {
        const ptr0 = passStringToWasm(s);
        const len0 = WASM_VECTOR_LEN;
        try {
            return TransactionId.__wrap(wasm.transactionid_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
}

function freeTransactionSignature(ptr) {

    wasm.__wbg_transactionsignature_free(ptr);
}
/**
*/
export class TransactionSignature {

    static __wrap(ptr) {
        const obj = Object.create(TransactionSignature.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTransactionSignature(ptr);
    }

    /**
    * @param {string} hex
    * @returns {TransactionSignature}
    */
    static from_hex(hex) {
        const ptr0 = passStringToWasm(hex);
        const len0 = WASM_VECTOR_LEN;
        try {
            return TransactionSignature.__wrap(wasm.transactionsignature_from_hex(ptr0, len0));

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    to_hex() {
        const retptr = globalArgumentPtr();
        wasm.transactionsignature_to_hex(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

function freeTxInput(ptr) {

    wasm.__wbg_txinput_free(ptr);
}
/**
*/
export class TxInput {

    static __wrap(ptr) {
        const obj = Object.create(TxInput.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTxInput(ptr);
    }

    /**
    * @param {TxoPointer} ptr
    * @param {TxOut} value
    * @returns {TxInput}
    */
    static new(ptr, value) {
        return TxInput.__wrap(wasm.txinput_new(ptr.ptr, value.ptr));
    }
    /**
    * @returns {any}
    */
    to_json() {
        return takeObject(wasm.txinput_to_json(this.ptr));
    }
    /**
    * @param {any} value
    * @returns {TxInput}
    */
    static from_json(value) {
        return TxInput.__wrap(wasm.txinput_from_json(addHeapObject(value)));
    }
}

function freeTxOut(ptr) {

    wasm.__wbg_txout_free(ptr);
}
/**
*/
export class TxOut {

    static __wrap(ptr) {
        const obj = Object.create(TxOut.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTxOut(ptr);
    }

    /**
    * @param {Address} address
    * @param {Coin} value
    * @returns {TxOut}
    */
    static new(address, value) {
        return TxOut.__wrap(wasm.txout_new(address.ptr, value.ptr));
    }
    /**
    * serialize into a JsValue object
    * @returns {any}
    */
    to_json() {
        return takeObject(wasm.txout_to_json(this.ptr));
    }
    /**
    * retrieve the object from a JsValue.
    * @param {any} value
    * @returns {TxOut}
    */
    static from_json(value) {
        return TxOut.__wrap(wasm.txout_from_json(addHeapObject(value)));
    }
}

function freeTxoPointer(ptr) {

    wasm.__wbg_txopointer_free(ptr);
}
/**
*/
export class TxoPointer {

    static __wrap(ptr) {
        const obj = Object.create(TxoPointer.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeTxoPointer(ptr);
    }

    /**
    * @param {TransactionId} id
    * @param {number} index
    * @returns {TxoPointer}
    */
    static new(id, index) {
        return TxoPointer.__wrap(wasm.txopointer_new(id.ptr, index));
    }
    /**
    * serialize into a JsValue object
    * @returns {any}
    */
    to_json() {
        return takeObject(wasm.txopointer_to_json(this.ptr));
    }
    /**
    * retrieve the object from a JsValue.
    * @param {any} value
    * @returns {TxoPointer}
    */
    static from_json(value) {
        return TxoPointer.__wrap(wasm.txopointer_from_json(addHeapObject(value)));
    }
}

function freeWitness(ptr) {

    wasm.__wbg_witness_free(ptr);
}
/**
*/
export class Witness {

    static __wrap(ptr) {
        const obj = Object.create(Witness.prototype);
        obj.ptr = ptr;

        return obj;
    }

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeWitness(ptr);
    }

    /**
    * @param {BlockchainSettings} blockchain_settings
    * @param {PrivateKey} signing_key
    * @param {TransactionId} transaction_id
    * @returns {Witness}
    */
    static new_extended_key(blockchain_settings, signing_key, transaction_id) {
        return Witness.__wrap(wasm.witness_new_extended_key(blockchain_settings.ptr, signing_key.ptr, transaction_id.ptr));
    }
    /**
    * @param {BlockchainSettings} blockchain_settings
    * @param {PrivateRedeemKey} signing_key
    * @param {TransactionId} transaction_id
    * @returns {Witness}
    */
    static new_redeem_key(blockchain_settings, signing_key, transaction_id) {
        return Witness.__wrap(wasm.witness_new_redeem_key(blockchain_settings.ptr, signing_key.ptr, transaction_id.ptr));
    }
    /**
    * used to add signatures created by hardware wallets where we don\'t have access
    * to the private key
    * @param {PublicKey} key
    * @param {TransactionSignature} signature
    * @returns {Witness}
    */
    static from_external(key, signature) {
        return Witness.__wrap(wasm.witness_from_external(key.ptr, signature.ptr));
    }
}

export function __wbindgen_object_drop_ref(i) { dropObject(i); }

