import {Hash, Key, KeyStore, PrivateKey, PublicKey, SecretKey} from "./key-store";
import {crypto, EC256_CURVE} from './crypto';

import {
    Sequence,
    Integer,
    OctetString, ObjectIdentifier
} from 'asn1js';

export abstract class KeyImpl<ALG extends string> implements Key<ALG> {
    protected abstract createCryptoKey(alg: ALG): Promise<CryptoKey>;
    private cryptoKeys: {[alg: string]: Promise<CryptoKey>} = {};
    getCryptoKey(algorithm: ALG): Promise<CryptoKey> {
        return this.cryptoKeys[algorithm] ??= this.createCryptoKey(algorithm);
    }
    protected getAnyCryptoKeyOr(algorithm: ALG): Promise<CryptoKey> {
        const names = Object.keys(this.cryptoKeys);
        if (names.length === 0) {
            return this.getCryptoKey(algorithm);
        } else {
            return this.cryptoKeys[names[0]];
        }
    }

    private hash$: Promise<Hash> | null = null;
    getHash(): Promise<Hash> {
        return this.hash$ ??= this.getBytes().then(
            raw => crypto.subtle.digest('SHA-256', raw)
        ).then(
            hash => Buffer.from(hash)
        );
    }

    private bytes$: Promise<Buffer> | null = null;
    protected abstract exportBytes(): Promise<Buffer>;
    getBytes(): Promise<Buffer> {
        return this.bytes$ ??= this.exportBytes();
    }
}

function decodeB64URL(encoded: string): Buffer {
    return Buffer.from(encoded.replace('-', '+').replace('_', '/'), 'base64')
}

export class InvalidAlgorithmError extends Error {
    constructor() {
        super('InvalidAlgorithm');
    }
}

export class InvalidInstanceError extends Error {
    constructor() {
        super('InvalidInstance');
    }
}

export class SecretKeyImpl extends KeyImpl<'AES'> implements SecretKey {
    constructor(readonly aesCryptoKey: CryptoKey) {
        super();
    }

    protected async createCryptoKey(alg: 'AES'): Promise<CryptoKey> {
        if (alg === 'AES') {
            return this.aesCryptoKey;
        } else {
            throw new InvalidAlgorithmError();
        }
    }

    protected async exportBytes(): Promise<Buffer> {
        return crypto.subtle.exportKey('raw', await this.getAnyCryptoKeyOr('AES')).then(
            raw => Buffer.from(raw)
        )
    }

    async equals(secretKey: SecretKey): Promise<boolean> {
        if (this === secretKey) {
            return true;
        } if (secretKey instanceof SecretKeyImpl) {
            return (await this.getBytes()).equals(await secretKey.getBytes())
        } else {
            throw new InvalidInstanceError();
        }
    }
}

export class PublicKeyImpl extends KeyImpl<'ECDSA' | 'ECDH'> implements PublicKey {
    constructor(readonly x: Buffer, readonly y: Buffer) {
        super();
    }

    private raw: Promise<Buffer> | null = null;
    private getRaw() {
        return this.raw ??= this.getBytes().then(bytes => Buffer.concat([_4, bytes]))
    }

    protected async createCryptoKey(algorithm: 'ECDSA' | 'ECDH'): Promise<CryptoKey> {
        if (algorithm === 'ECDSA') {
            return await crypto.subtle.importKey('raw', await this.getRaw(), {
                name: 'ECDSA',
                namedCurve: EC256_CURVE
            }, true, [
                'verify'
            ]);
        } else if (algorithm === 'ECDH') {
            return await crypto.subtle.importKey('raw', await this.getRaw(), {
                name: 'ECDH',
                namedCurve: EC256_CURVE
            }, true, [
                'deriveKey'
            ]);
        } else {
            throw new InvalidAlgorithmError();
        }
    }

    protected async exportBytes(): Promise<Buffer> {
        return Buffer.concat([
            this.x, this.y
        ]);
    }

    async getXBytes(): Promise<Buffer> {
        return this.x;
    }

    async getYBytes(): Promise<Buffer> {
        return this.y;
    }

    async equals(publicKey: PublicKey): Promise<boolean> {
        if (this === publicKey) {
            return true;
        } else if (publicKey instanceof PublicKeyImpl) {
            return this.x.equals(publicKey.x) && this.y.equals(publicKey.y);
        } else {
            throw new InvalidInstanceError();
        }
    }
}
export class PrivateKeyImpl extends KeyImpl<'ECDSA' | 'ECDH'> implements PrivateKey {
    constructor(readonly key: Buffer) {
        super();
    }


    private pkcs8: ArrayBuffer | null = null;
    private getPKCS8() {
        return this.pkcs8 ??= privateKeyToPKCS8(this.key)
    }

    protected async createCryptoKey(algorithm: 'ECDSA' | 'ECDH'): Promise<CryptoKey> {
        if (algorithm === 'ECDSA') {
            return await crypto.subtle.importKey('pkcs8', this.getPKCS8(), {
                name: 'ECDSA',
                namedCurve: EC256_CURVE
            }, true, [
                'sign'
            ]);
        } else if (algorithm === 'ECDH') {
            return await crypto.subtle.importKey('pkcs8', this.getPKCS8(), {
                name: 'ECDH',
                namedCurve: EC256_CURVE
            }, true, [
                'deriveKey'
            ]);
        } else {
            throw new InvalidAlgorithmError();
        }
    }

    protected async exportBytes(): Promise<Buffer> {
        return this.key;
    }

    private publicKey$: Promise<PublicKey> | null = null;
    async getPublicKey(): Promise<PublicKey> {
        return this.publicKey$ ??= crypto.subtle.exportKey(
            'jwk', await this.getAnyCryptoKeyOr('ECDSA')
        ).then(
            ({x, y}) => importPublicKey(
                decodeB64URL(x), decodeB64URL(y)
            )
        )
    }

    async equals(privateKey: PrivateKey): Promise<boolean> {
        if (this === privateKey) {
            return true;
        } else if (privateKey instanceof PrivateKeyImpl) {
            return this.key.equals(privateKey.key);
        } else {
            throw new InvalidInstanceError();
        }
    }
}

export class InvalidKeyLengthError extends Error {
    constructor() {
        super('InvalidKeyLength');
    }
}

export async function createSecretKey(
    bytes: Uint8Array = crypto.getRandomValues(new Uint8Array(32))
): Promise<SecretKey> {
    if (bytes.length !== 32) {
        throw new InvalidKeyLengthError();
    }

    return new SecretKeyImpl(
        await crypto.subtle.importKey('raw', bytes, {
            name: 'AES-CBC',
            length: 256
        }, true, ['encrypt', 'decrypt'])
    );
}

const _4 = Buffer.from('04', 'hex');
export async function importPublicKey(
    x: Buffer, y: Buffer
): Promise<PublicKey> {
    return new PublicKeyImpl(
        x, y
    );
}
export async function importPublicKeyXY(
    xy: Buffer
): Promise<PublicKey> {
    return new PublicKeyImpl(
        xy.subarray(0, 32),
        xy.subarray(32, 64)
    );
}

function privateKeyToPKCS8(bytes: Uint8Array) {
    if (bytes.length !== 32) {
        throw new InvalidKeyLengthError();
    }

    const identifierSequence = new Sequence();
    identifierSequence.valueBlock.value.push(
        new ObjectIdentifier({
            value: '1.2.840.10045.2.1'
        }),
        new ObjectIdentifier({
            value: '1.2.840.10045.3.1.7'
        })
    );

    const privateKeySequence = new Sequence();
    privateKeySequence.valueBlock.value.push(
        new Integer({
            value: 1
        }),
        new OctetString({
            valueHex: bytes
        })
    );

    const sequence = new Sequence();
    sequence.valueBlock.value.push(
        new Integer({
            value: 0
        }),
        identifierSequence,
        new OctetString({
            valueHex: privateKeySequence.toBER()
        })
    );

    return sequence.toBER();
}

export async function createPrivateKey(
    bytes: Uint8Array = crypto.getRandomValues(new Uint8Array(32))
): Promise<PrivateKey> {
    if (bytes.length !== 32) {
        throw new InvalidKeyLengthError();
    }

    return new PrivateKeyImpl(
        Buffer.from(bytes)
    );
}

export class KeyStoreImpl implements KeyStore {
    private secretKeys: {hash: Hash, bytes: Buffer, key: SecretKey}[] = [];
    private ecKeys: {pubBytes: Buffer, priBytes: Buffer, pub: PublicKey, pri: PrivateKey}[] = [];
    private derivedKeys: {pubBytesA: Buffer, pubBytesB: Buffer, key: SecretKey}[] = [];

    async deriveKey(publicKey: PublicKey, privateKey: PrivateKey): Promise<SecretKey | undefined> {
        const pubB = await privateKey.getPublicKey();
        const pubBytesB = await pubB.getBytes();

        const pubBytesA = await publicKey.getBytes();

        const cached = this.derivedKeys.find(
            entry => entry.pubBytesA.equals(pubBytesA) && entry.pubBytesB.equals(pubBytesB)
        );

        if (cached == null) {
            const key = new SecretKeyImpl(
                await crypto.subtle.deriveKey(
                    {
                        name: 'ECDH',
                        public: await publicKey.getCryptoKey('ECDH')
                    }, await privateKey.getCryptoKey('ECDH'), {
                        name: 'AES-CBC',
                        length: 256
                    },
                    false,
                    [
                        'decrypt', 'encrypt'
                    ]
                )
            );

            this.derivedKeys.push(
                {
                    pubBytesA,
                    pubBytesB,
                    key
                },
                {
                    pubBytesA: pubBytesB,
                    pubBytesB: pubBytesA,
                    key
                }
            );

            return key;
        } else {
            return cached.key;
        }
    }

    async getSecretKey(keyHash: Hash): Promise<SecretKey | undefined> {
        return this.secretKeys.find(
            ({hash}) => hash.equals(keyHash)
        )?.key;
    }

    async getPrivateKey(publicKey: PublicKey): Promise<PrivateKey | undefined> {
        const bytes = await publicKey.getBytes();
        return this.ecKeys.find(
            ({pubBytes}) => pubBytes.equals(bytes)
        )?.pri;
    }

    async putSecretKey(secretKey: SecretKey): Promise<void> {
        const keyBytes = await secretKey.getBytes();

        if (
            this.secretKeys.find(
                ({bytes}) => keyBytes.equals(bytes)
            ) == null
        ) {
            const hash = await secretKey.getHash();
            this.secretKeys.push({
                key: secretKey,
                hash,
                bytes: keyBytes
            });
        }
    }

    async putPrivateKey(privateKey: PrivateKey): Promise<void> {
        const bytes = await privateKey.getBytes();

        if (
            this.ecKeys.find(
                ({priBytes}) => priBytes.equals(bytes)
            ) == null
        ) {
            const pub = await privateKey.getPublicKey();
            const pubBytes = await pub.getBytes();

            this.ecKeys.push({
                priBytes: bytes,
                pri: privateKey,
                pubBytes,
                pub
            });
        }
    }
}