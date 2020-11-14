import {Hash, Key, KeyStore, PrivateKey, PublicKey, SecretKey} from "./key-store";
import {crypto, EC256_CURVE} from './crypto';

export class KeyImpl implements Key {
    constructor(
        readonly cryptoKey: CryptoKey
    ) {
    }

    async getCryptoKey(): Promise<CryptoKey> {
        return this.cryptoKey;
    }

    private hash$: Promise<Hash> | null = null;
    getHash(): Promise<Hash> {
        return this.hash$ ??= this.getRaw().then(
            raw => crypto.subtle.digest('SHA-256', raw)
        ).then(
            hash => Buffer.from(hash)
        );
    }

    private raw$: Promise<Buffer> | null = null;
    getRaw(): Promise<Buffer> {
        return this.raw$ ??= crypto.subtle.exportKey('raw', this.cryptoKey).then(
            raw => Buffer.from(raw)
        );
    }
}

export class SecretKeyImpl extends KeyImpl implements SecretKey {}

export class PublicKeyImpl extends KeyImpl implements PublicKey {}
export class PrivateKeyImpl extends KeyImpl implements PrivateKey {

    private publicKey$: Promise<PublicKey> | null = null;
    getPublicKey(): Promise<PublicKey> {
        return this.publicKey$ ??= crypto.subtle.exportKey(
            'jwk', this.cryptoKey
        ).then(
            ({d, ...jwk}) => crypto.subtle.importKey(
                'jwk', jwk, {
                    name: jwk.kty,
                    namedCurve: jwk.crv
                }, true, [
                    'encrypt',
                    'verify'
                ]
            )
        ).then(
            pubCryptoKey => new PublicKeyImpl(pubCryptoKey)
        )
    }
}

export class InvalidKeyLengthError extends Error {}

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

export async function createPrivateKey(
    bytes: Uint8Array = crypto.getRandomValues(new Uint8Array(32))
): Promise<PrivateKey> {
    if (bytes.length !== 32) {
        throw new InvalidKeyLengthError();
    }

    return new PrivateKeyImpl(
        await crypto.subtle.importKey(
            'raw', bytes, {
                name: 'ECDSA',
                namedCurve: EC256_CURVE
            }, true, ['sign', 'verify', 'deriveKey']
        )
    );
}

export class KeyStoreImpl implements KeyStore {
    private secretKeys: {hash: Hash, raw: Buffer, key: SecretKey}[] = [];
    private ecKeys: {rawPub: Buffer, rawPri: Buffer, pub: PublicKey, pri: PrivateKey}[] = [];

    async getSecretKey(keyHash: Hash): Promise<SecretKey | undefined> {
        return this.secretKeys.find(
            ({hash}) => hash.equals(keyHash)
        )?.key;
    }

    async getPrivateKey(publicKey: PublicKey): Promise<PrivateKey | undefined> {
        const raw = await publicKey.getRaw();
        return this.ecKeys.find(
            ({rawPub}) => rawPub.equals(raw)
        )?.pri;
    }

    async putSecretKey(secretKey: SecretKey): Promise<void> {
        const keyRaw = await secretKey.getRaw();

        if (
            this.secretKeys.find(
                ({raw}) => raw.equals(keyRaw)
            ) == null
        ) {
            const hash = await secretKey.getHash();
            this.secretKeys.push({
                key: secretKey,
                hash: hash,
                raw: keyRaw
            });
        }
    }

    async putPrivateKey(privateKey: PrivateKey): Promise<void> {
        const keyRaw = await privateKey.getRaw();

        if (
            this.ecKeys.find(
                ({rawPri}) => rawPri.equals(keyRaw)
            ) == null
        ) {
            const pub = await privateKey.getPublicKey();
            const rawPub = await pub.getRaw();

            this.ecKeys.push({
                rawPri: keyRaw,
                pri: privateKey,
                rawPub,
                pub
            });
        }
    }
}