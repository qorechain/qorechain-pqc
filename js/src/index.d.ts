export interface KeyPair { publicKey: Uint8Array; secretKey: Uint8Array; }
export interface SigScheme {
  readonly name: string;
  keygen(seed?: Uint8Array): KeyPair;
  sign(secretKey: Uint8Array, message: Uint8Array): Uint8Array;
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
export function hybridSignBytes(bodyWithoutPqcExt: Uint8Array, authInfoBytes: Uint8Array): Uint8Array;
export function batchVerify(scheme: SigScheme, items: { publicKey: Uint8Array; message: Uint8Array; signature: Uint8Array }[]): number;
export const VERSION: string;
