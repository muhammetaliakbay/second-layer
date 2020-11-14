import {PreSharedKey, KeyHash, PublicKey, PrivateKey} from "./second-layer";

export interface KeyStore {
    getPreSharedKey(keyHash: KeyHash): PreSharedKey | undefined;
    getPrivateKey(publicKey: PublicKey): PrivateKey | undefined;

    putPrivateKey(privateKey: PrivateKey): void;
    putPreSharedKey(preSharedKey: PreSharedKey): void;
}