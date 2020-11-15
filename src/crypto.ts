declare module 'crypto' {
    export const webcrypto: Crypto;
}

// checking if 'window' is defined (in browser) and if it is defined then trying to get crypto variable which contains 'Crypto' (webcrypto)
// if it is a browser and supports webcrypto, 'browserCrypto' variable contains Crypto instance, undefined otherwise
const browserCrypto = typeof window === 'undefined' ? undefined : window.crypto;

// if 'browserCrypto' is not undefined, use it. If it is undefined then use nodejs's webcrypto implementation
export const crypto = browserCrypto ?? require('crypto').webcrypto;

// second-layer protocol uses P-256 standards of elliptic cure cryptography
export const EC256_CURVE = 'P-256';
