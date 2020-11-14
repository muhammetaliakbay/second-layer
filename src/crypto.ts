declare module 'crypto' {
    export const webcrypto: Crypto;
}

const browserCrypto = typeof window === 'undefined' ? undefined : window.crypto;

export const crypto = browserCrypto ?? require('crypto').webcrypto;

export const EC256_CURVE = 'P-256';
