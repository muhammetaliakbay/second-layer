export type Hash = Buffer;

export interface HasRaw {
    getRaw(): Promise<Buffer>
}
export interface HasCryptoKey {
    getCryptoKey(): Promise<CryptoKey>
}
export interface HasHash {
    getHash(): Promise<Hash>
}

export interface Key extends HasCryptoKey, HasHash, HasRaw {

}

export interface SecretKey extends Key {

}
export interface PublicKey extends Key  {

}
export interface PrivateKey extends Key  {
    getPublicKey(): Promise<PublicKey>
}

export interface KeyStore {
    getSecretKey(keyHash: Hash): Promise<SecretKey | undefined>;
    getPrivateKey(publicKey: PublicKey): Promise<PrivateKey | undefined>;

    putPrivateKey(privateKey: PrivateKey): Promise<void>;
    putSecretKey(preSharedKey: SecretKey): Promise<void>;
}