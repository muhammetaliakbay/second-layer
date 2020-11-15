export type Hash = Buffer;

export interface HasBytes {
    getBytes(): Promise<Buffer>
}
export interface HasCryptoKey<ALG extends string> {
    getCryptoKey(algorithm: ALG): Promise<CryptoKey>
}
export interface HasHash {
    getHash(): Promise<Hash>
}

export interface Key<ALG extends string> extends HasCryptoKey<ALG>, HasHash, HasBytes {

}

export interface SecretKey extends Key<'AES'> {

}
export interface PublicKey extends Key<'ECDSA' | 'ECDH'>  {
    getXBytes(): Promise<Buffer>;
    getYBytes(): Promise<Buffer>;
}
export interface PrivateKey extends Key<'ECDSA' | 'ECDH'>  {
    getPublicKey(): Promise<PublicKey>
}

export interface KeyStore {
    getSecretKey(keyHash: Hash): Promise<SecretKey | undefined>;
    getPrivateKey(publicKey: PublicKey): Promise<PrivateKey | undefined>;

    deriveKey(publicKey: PublicKey, privateKey: PrivateKey): Promise<SecretKey | undefined>;

    putPrivateKey(privateKey: PrivateKey): Promise<void>;
    putSecretKey(preSharedKey: SecretKey): Promise<void>;
}