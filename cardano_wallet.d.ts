/* tslint:disable */
/**
* @param {Entropy} entropy 
* @param {Uint8Array} iv 
* @param {string} password 
* @returns {any} 
*/
export function paper_wallet_scramble(entropy: Entropy, iv: Uint8Array, password: string): any;
/**
* @param {Uint8Array} paper 
* @param {string} password 
* @returns {Entropy} 
*/
export function paper_wallet_unscramble(paper: Uint8Array, password: string): Entropy;
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
export function password_encrypt(password: string, salt: Uint8Array, nonce: Uint8Array, data: Uint8Array): any;
/**
* decrypt the data with the password
*
* @param {string} password 
* @param {Uint8Array} encrypted_data 
* @returns {any} 
*/
export function password_decrypt(password: string, encrypted_data: Uint8Array): any;
/**
*/
export class AccountIndex {
  free(): void;
  static new(index: number): AccountIndex;
}
/**
*/
export class Address {
  free(): void;
  to_base58(): string;
  static from_base58(s: string): Address;
}
/**
*/
export class AddressKeyIndex {
  free(): void;
  static new(index: number): AddressKeyIndex;
}
/**
*/
export class Bip44AccountPrivate {
  free(): void;
  static new(key: PrivateKey, derivation_scheme: DerivationScheme): Bip44AccountPrivate;
  public(): Bip44AccountPublic;
  address_key(internal: boolean, index: AddressKeyIndex): PrivateKey;
  key(): PrivateKey;
}
/**
*/
export class Bip44AccountPublic {
  free(): void;
  static new(key: PublicKey, derivation_scheme: DerivationScheme): Bip44AccountPublic;
  address_key(internal: boolean, index: AddressKeyIndex): PublicKey;
  key(): PublicKey;
}
/**
* Root Private Key of a BIP44 HD Wallet
*/
export class Bip44RootPrivateKey {
  free(): void;
  static new(key: PrivateKey, derivation_scheme: DerivationScheme): Bip44RootPrivateKey;
  static recover(entropy: Entropy, password: string): Bip44RootPrivateKey;
  bip44_account(index: AccountIndex): Bip44AccountPrivate;
  key(): PrivateKey;
}
/**
* setting of the blockchain
*
* This includes the `ProtocolMagic` a discriminant value to differentiate
* different instances of the cardano blockchain (Mainnet, Testnet... ).
*/
export class BlockchainSettings {
  free(): void;
  to_json(): any;
  static from_json(value: any): BlockchainSettings;
  static mainnet(): BlockchainSettings;
}
/**
*/
export class Coin {
  free(): void;
  constructor();
  static from_str(s: string): Coin;
  to_str(): string;
  static from(ada: number, lovelace: number): Coin;
  ada(): number;
  lovelace(): number;
  add(other: Coin): Coin;
}
/**
*/
export class CoinDiff {
  free(): void;
  is_zero(): boolean;
  is_negative(): boolean;
  is_positive(): boolean;
  value(): Coin;
}
/**
*/
export class DaedalusAddressChecker {
  free(): void;
  static new(wallet: DaedalusWallet): DaedalusAddressChecker;
  check_address(address: Address): DaedalusCheckedAddress;
}
/**
* result value of the check_address function of the DaedalusAddressChecker.
*
* If the address passed to check_address was recognised by the daedalus wallet
* then this object will contain the private key associated to this wallet
* private key necessary to sign transactions
*/
export class DaedalusCheckedAddress {
  free(): void;
  is_checked(): boolean;
  private_key(): PrivateKey;
}
/**
*/
export class DaedalusWallet {
  free(): void;
  static new(key: PrivateKey): DaedalusWallet;
  static recover(entropy: Entropy): DaedalusWallet;
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
  free(): void;
  static v1(): DerivationScheme;
  static v2(): DerivationScheme;
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
  free(): void;
  static from_english_mnemonics(mnemonics: string): Entropy;
  to_english_mnemonics(): string;
  to_array(): any;
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
  free(): void;
  static default(): LinearFeeAlgorithm;
}
/**
* This is the Output policy for automatic Input selection.
*/
export class OutputPolicy {
  free(): void;
  static change_to_one_address(address: Address): OutputPolicy;
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
  free(): void;
  static new(entropy: Entropy, password: string): PrivateKey;
  static from_hex(hex: string): PrivateKey;
  to_hex(): string;
  public(): PublicKey;
  sign(data: Uint8Array): Signature;
  derive(derivation_scheme: DerivationScheme, index: number): PrivateKey;
}
/**
*/
export class PrivateRedeemKey {
  free(): void;
  static from_bytes(bytes: Uint8Array): PrivateRedeemKey;
  static from_hex(hex: string): PrivateRedeemKey;
  to_hex(): string;
  public(): PublicRedeemKey;
  sign(data: Uint8Array): RedeemSignature;
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
  free(): void;
  static from_hex(hex: string): PublicKey;
  to_hex(): string;
  verify(data: Uint8Array, signature: Signature): boolean;
  derive(derivation_scheme: DerivationScheme, index: number): PublicKey;
  bootstrap_era_address(blockchain_settings: BlockchainSettings): Address;
}
/**
*/
export class PublicRedeemKey {
  free(): void;
  static from_hex(hex: string): PublicRedeemKey;
  to_hex(): string;
  verify(data: Uint8Array, signature: RedeemSignature): boolean;
  address(settings: BlockchainSettings): Address;
}
/**
*/
export class RedeemSignature {
  free(): void;
  static from_hex(hex: string): RedeemSignature;
  to_hex(): string;
}
/**
*/
export class Signature {
  free(): void;
  static from_hex(hex: string): Signature;
  to_hex(): string;
}
/**
* a signed transaction, ready to be sent to the network.
*/
export class SignedTransaction {
  free(): void;
  id(): string;
  to_json(): any;
  to_hex(): string;
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
  free(): void;
  id(): string;
  to_json(): any;
  to_hex(): string;
}
/**
* The transaction builder provides a set of tools to help build
* a valid Transaction.
*/
export class TransactionBuilder {
  free(): void;
  constructor();
  add_input(txo_pointer: TxoPointer, value: Coin): void;
  get_input_total(): Coin;
  add_output(output: TxOut): void;
  apply_output_policy(fee_algorithm: LinearFeeAlgorithm, policy: OutputPolicy): any;
  get_output_total(): Coin;
  estimate_fee(fee_algorithm: LinearFeeAlgorithm): Coin;
  get_balance(fee_algorithm: LinearFeeAlgorithm): CoinDiff;
  get_balance_without_fees(): CoinDiff;
  make_transaction(): Transaction;
}
/**
*/
export class TransactionFinalized {
  free(): void;
  constructor(transaction: Transaction);
  sign(blockchain_settings: BlockchainSettings, key: PrivateKey): void;
  sign_redemption(blockchain_settings: BlockchainSettings, key: PrivateRedeemKey): void;
  from_external(key: PublicKey, signature: TransactionSignature): void;
  finalize(): SignedTransaction;
}
/**
*/
export class TransactionId {
  free(): void;
}
/**
*/
export class TransactionSignature {
  free(): void;
  static from_hex(hex: string): TransactionSignature;
  to_hex(): string;
}
/**
*/
export class TxOut {
  free(): void;
  to_json(): any;
  static from_json(value: any): TxOut;
}
/**
*/
export class TxoPointer {
  free(): void;
  to_json(): any;
  static from_json(value: any): TxoPointer;
}
