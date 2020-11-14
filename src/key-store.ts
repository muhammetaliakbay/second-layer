import {PreSharedKey, KeyHash, PublicKey, PrivateKey} from "./second-layer";

export interface KeyStore {
    getPreShareKey(keyHash: KeyHash): PreSharedKey | undefined;
    getPrivateKey(publicKey: PublicKey): PrivateKey | undefined;
}