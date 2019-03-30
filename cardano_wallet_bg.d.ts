/* tslint:disable */
export const memory: WebAssembly.Memory;
export function __wbindgen_global_argument_ptr(): number;
export function __wbg_blockchainsettings_free(a: number): void;
export function blockchainsettings_to_json(a: number): number;
export function blockchainsettings_from_json(a: number): number;
export function blockchainsettings_mainnet(): number;
export function __wbg_derivationscheme_free(a: number): void;
export function derivationscheme_v1(): number;
export function derivationscheme_v2(): number;
export function __wbg_entropy_free(a: number): void;
export function entropy_from_english_mnemonics(a: number, b: number): number;
export function entropy_to_english_mnemonics(a: number, b: number): void;
export function __wbg_privatekey_free(a: number): void;
export function privatekey_new(a: number, b: number, c: number): number;
export function privatekey_from_hex(a: number, b: number): number;
export function privatekey_to_hex(a: number, b: number): void;
export function privatekey_public(a: number): number;
export function privatekey_sign(a: number, b: number, c: number): number;
export function privatekey_derive(a: number, b: number, c: number): number;
export function __wbg_publickey_free(a: number): void;
export function publickey_from_hex(a: number, b: number): number;
export function publickey_to_hex(a: number, b: number): void;
export function publickey_verify(a: number, b: number, c: number, d: number): number;
export function publickey_derive(a: number, b: number, c: number): number;
export function publickey_bootstrap_era_address(a: number, b: number): number;
export function __wbg_address_free(a: number): void;
export function address_to_base58(a: number, b: number): void;
export function address_from_base58(a: number, b: number): number;
export function __wbg_signature_free(a: number): void;
export function signature_from_hex(a: number, b: number): number;
export function signature_to_hex(a: number, b: number): void;
export function __wbg_accountindex_free(a: number): void;
export function accountindex_new(a: number): number;
export function __wbg_addresskeyindex_free(a: number): void;
export function addresskeyindex_new(a: number): number;
export function __wbg_bip44rootprivatekey_free(a: number): void;
export function bip44rootprivatekey_new(a: number, b: number): number;
export function bip44rootprivatekey_recover(a: number, b: number, c: number): number;
export function bip44rootprivatekey_bip44_account(a: number, b: number): number;
export function bip44rootprivatekey_key(a: number): number;
export function __wbg_bip44accountprivate_free(a: number): void;
export function bip44accountprivate_new(a: number, b: number): number;
export function bip44accountprivate_public(a: number): number;
export function bip44accountprivate_address_key(a: number, b: number, c: number): number;
export function bip44accountprivate_key(a: number): number;
export function __wbg_bip44accountpublic_free(a: number): void;
export function bip44accountpublic_new(a: number, b: number): number;
export function bip44accountpublic_address_key(a: number, b: number, c: number): number;
export function bip44accountpublic_key(a: number): number;
export function __wbg_daedaluswallet_free(a: number): void;
export function daedaluswallet_recover(a: number): number;
export function __wbg_daedalusaddresschecker_free(a: number): void;
export function daedalusaddresschecker_new(a: number): number;
export function daedalusaddresschecker_check_address(a: number, b: number): number;
export function __wbg_daedaluscheckedaddress_free(a: number): void;
export function daedaluscheckedaddress_is_checked(a: number): number;
export function daedaluscheckedaddress_private_key(a: number): number;
export function __wbg_coindiff_free(a: number): void;
export function coindiff_is_zero(a: number): number;
export function coindiff_is_negative(a: number): number;
export function coindiff_is_positive(a: number): number;
export function coindiff_value(a: number): number;
export function __wbg_coin_free(a: number): void;
export function coin_new(): number;
export function coin_from_str(a: number, b: number): number;
export function coin_to_str(a: number, b: number): void;
export function coin_from(a: number, b: number): number;
export function coin_ada(a: number): number;
export function coin_lovelace(a: number): number;
export function coin_add(a: number, b: number): number;
export function __wbg_transactionid_free(a: number): void;
export function __wbg_txopointer_free(a: number): void;
export function txopointer_to_json(a: number): number;
export function txopointer_from_json(a: number): number;
export function __wbg_txout_free(a: number): void;
export function txout_to_json(a: number): number;
export function txout_from_json(a: number): number;
export function __wbg_transaction_free(a: number): void;
export function transaction_id(a: number, b: number): void;
export function transaction_to_json(a: number): number;
export function transaction_to_hex(a: number, b: number): void;
export function transaction_to_base58(a: number, b: number): void;
export function __wbg_signedtransaction_free(a: number): void;
export function signedtransaction_id(a: number, b: number): void;
export function signedtransaction_to_json(a: number): number;
export function signedtransaction_to_hex(a: number, b: number): void;
export function signedtransaction_to_base58(a: number, b: number): void;
export function __wbg_linearfeealgorithm_free(a: number): void;
export function linearfeealgorithm_default(): number;
export function __wbg_outputpolicy_free(a: number): void;
export function outputpolicy_change_to_one_address(a: number): number;
export function __wbg_transactionbuilder_free(a: number): void;
export function transactionbuilder_new(): number;
export function transactionbuilder_add_input(a: number, b: number, c: number): void;
export function transactionbuilder_get_input_total(a: number): number;
export function transactionbuilder_add_output(a: number, b: number): void;
export function transactionbuilder_apply_output_policy(a: number, b: number, c: number): number;
export function transactionbuilder_get_output_total(a: number): number;
export function transactionbuilder_estimate_fee(a: number, b: number): number;
export function transactionbuilder_get_balance(a: number, b: number): number;
export function transactionbuilder_get_balance_without_fees(a: number): number;
export function transactionbuilder_make_transaction(a: number): number;
export function __wbg_transactionfinalized_free(a: number): void;
export function transactionfinalized_new(a: number): number;
export function transactionfinalized_sign(a: number, b: number, c: number): void;
export function transactionfinalized_finalize(a: number): number;
export function __wbg_privateredeemkey_free(a: number): void;
export function privateredeemkey_from_bytes(a: number, b: number): number;
export function privateredeemkey_from_hex(a: number, b: number): number;
export function privateredeemkey_to_hex(a: number, b: number): void;
export function privateredeemkey_public(a: number): number;
export function privateredeemkey_sign(a: number, b: number, c: number): number;
export function __wbg_publicredeemkey_free(a: number): void;
export function publicredeemkey_from_hex(a: number, b: number): number;
export function publicredeemkey_to_hex(a: number, b: number): void;
export function publicredeemkey_verify(a: number, b: number, c: number, d: number): number;
export function publicredeemkey_address(a: number, b: number): number;
export function __wbg_redeemsignature_free(a: number): void;
export function redeemsignature_from_hex(a: number, b: number): number;
export function redeemsignature_to_hex(a: number, b: number): void;
export function paper_wallet_scramble(a: number, b: number, c: number, d: number, e: number): number;
export function paper_wallet_unscramble(a: number, b: number, c: number, d: number): number;
export function password_encrypt(a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number): number;
export function password_decrypt(a: number, b: number, c: number, d: number): number;
export function __wbindgen_malloc(a: number): number;
export function __wbindgen_realloc(a: number, b: number, c: number): number;
export function __wbindgen_free(a: number, b: number): void;
