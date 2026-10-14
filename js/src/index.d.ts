export interface KeyPair { publicKey: Uint8Array; secretKey: Uint8Array; }
export interface SignOptions {
  /**
   * Randomized (hedged) signing per FIPS-204. Default false: signatures are
   * DETERMINISTIC, as required by QoreChain's on-chain PQC verifier and matched
   * by the shared cross-language test vectors. Only set true for non-chain uses.
   */
  hedged?: boolean;
}
export interface SigScheme {
  readonly name: string;
  keygen(seed?: Uint8Array): KeyPair;
  sign(secretKey: Uint8Array, message: Uint8Array, opts?: SignOptions): Uint8Array;
  /** Never throws: malformed input returns false. */
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}
export interface KemScheme {
  readonly name: string;
  keygen(seed?: Uint8Array): KeyPair;
  encapsulate(publicKey: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
  decapsulate(secretKey: Uint8Array, cipherText: Uint8Array): Uint8Array;
}
export const mldsa44: SigScheme; export const mldsa65: SigScheme; export const mldsa87: SigScheme;
export const mlkem512: KemScheme; export const mlkem768: KemScheme; export const mlkem1024: KemScheme;
export const mldsa: SigScheme; export const mlkem: KemScheme;
export function shake256(data: Uint8Array, outLen?: number): Uint8Array;
export function pubkeyHash(publicKey: Uint8Array, len?: number): Uint8Array;
export type SignBytesVersion = 'v1' | 'v2';
export const HYBRID_SIGN_BYTES_V2_DOMAIN: 'qorechain-pqc-hybrid-v2';
/** Alias of HYBRID_SIGN_BYTES_V2_DOMAIN. */
export const HYBRID_SIGN_BYTES_DOMAIN: 'qorechain-pqc-hybrid-v2';
/** Every upgrade-plan name that switched a network to v2, newest first. */
export const SIGN_BYTES_V2_UPGRADES: readonly ['v3.2.0', 'v3.1.98'];
/** @deprecated The primary name only; a network may have switched under any name in SIGN_BYTES_V2_UPGRADES. */
export const SIGN_BYTES_V2_UPGRADE: 'v3.2.0';
export const LEGACY_SIGN_BYTES_CHAINS: readonly string[];
/** Legacy v1: BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth. */
export function hybridSignBytesV1(bodyWithoutPqcExt: Uint8Array, authInfoBytes: Uint8Array): Uint8Array;
/** v2: domain ‖ BE64(len chainId) ‖ chainId ‖ BE32(len b0) ‖ b0 ‖ BE32(len auth) ‖ auth. */
export function hybridSignBytesV2(chainId: string, bodyWithoutPqcExt: Uint8Array, authInfoBytes: Uint8Array): Uint8Array;
/** Version-dispatching builder; `version` is required. */
export function hybridSignBytes(version: SignBytesVersion, chainId: string, bodyWithoutPqcExt: Uint8Array, authInfoBytes: Uint8Array): Uint8Array;
/** Mirror of the chain's SignBytesVersionFor (height compared numerically). */
export function signBytesVersionFor(chainId: string, v2AppliedHeight: string | number | bigint | null | undefined): SignBytesVersion;
/** signBytesVersionFor over every name in SIGN_BYTES_V2_UPGRADES: the greatest applied height decides. */
export function signBytesVersionForApplied(chainId: string, appliedHeights: Record<string, string | number | bigint | null | undefined> | Map<string, string | number | bigint | null | undefined> | null | undefined): SignBytesVersion;
export function batchVerify(scheme: SigScheme, items: { publicKey: Uint8Array; message: Uint8Array; signature: Uint8Array }[]): number;
export const VERSION: string;
