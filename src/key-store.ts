// Hash is simply a Buffer. But it may be changed later
export type Hash = Buffer;

export interface HasBytes {
    /**
     * @returns bytes to store and reproduce the key
     */
    getBytes(): Promise<Buffer>
}

export interface HasCryptoKey<ALG extends string> {
    /**
     * CryptoKey is a type defined in WebCrypto API. It must be created with algorithm parameter.
     * Same key instance can not be used in ECDSA and ECDH, as an example.
     * @param algorithm Algorithm to be used while creating the key instance
     * @returns CryptoKey to be used in specified algorithm
     */
    getCryptoKey(algorithm: ALG): Promise<CryptoKey>
}

export interface HasHash {
    /**
     * @returns Hash of the key's bytes
     */
    getHash(): Promise<Hash>
}

export interface Key<ALG extends string> extends HasCryptoKey<ALG>, HasHash, HasBytes {
}

export interface SecretKey extends Key<'AES'> {
    equals(secretKey: SecretKey): Promise<boolean>;
}

export interface PublicKey extends Key<'ECDSA' | 'ECDH'>  {
    /**
     * Elliptic Curve Public keys are vectors. And it has X and Y components.
     * @returns bytes X components of the public-key
     */
    getXBytes(): Promise<Buffer>;

    /**
     * Elliptic Curve Public keys are vectors. And it has X and Y components.
     * @returns bytes Y components of the public-key
     */
    getYBytes(): Promise<Buffer>;

    equals(publicKey: PublicKey): Promise<boolean>;
}

export interface PrivateKey extends Key<'ECDSA' | 'ECDH'>  {
    /**
     * @returns Calculated public-key using private-key
     */
    getPublicKey(): Promise<PublicKey>;

    equals(privateKey: PrivateKey): Promise<boolean>;
}

export interface KeyStore {
    /**
     * @param keyHash Hash of the secret-key which currently looking for
     * @returns Secret key which its hash is equals with the one in parameter. Or undefined if not found.
     */
    getSecretKey(keyHash: Hash): Promise<SecretKey | undefined>;
    /**
     * @param publicKey PublicKey of the private-key which currently looking for
     * @returns Private key which its public key is equals with the one in parameter. Or undefined if not found.
     */
    getPrivateKey(publicKey: PublicKey): Promise<PrivateKey | undefined>;

    /**
     * @param publicKey Public key used in ECDH key derivation algorithm
     * @param privateKey Private key used in ECDH key derivation algorithm
     * @returns Derived secret-key as a result of ECDH algorithm with symmetric keys by parameters
     */
    deriveKey(publicKey: PublicKey, privateKey: PrivateKey): Promise<SecretKey>;

    /**
     * Matches and stores private and public keys in to the store to be used in future.
     * @param privateKey Private key to store
     */
    putPrivateKey(privateKey: PrivateKey): Promise<void>;
    /**
     * Stores the secret key in to the store to be used in future.
     * @param secretKey Secret key to store
     */
    putSecretKey(secretKey: SecretKey): Promise<void>;
}