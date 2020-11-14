import { assert, expect } from "chai";
import {createPrivateKey, createSecretKey} from "./key-store-impl";

describe('KeyStore tests', () => {

    it('checking secret-key', async () => {

        const secretKey = await createSecretKey();

        const keyRaw = await secretKey.getRaw();
        expect(keyRaw.length).equals(32, 'Secret Key (AES-256) must be 32 bytes long');

        const keyHash = await secretKey.getHash();
        expect(keyHash.length).equals(32, 'Secret Key\'s Hash (SHA-256) must be 32 bytes long');

    });

    it('checking ec-key', async () => {

        const privateKey = await createPrivateKey();

        const keyRaw = await privateKey.getRaw();
        expect(keyRaw.length).equals(32, 'Private Key (EC-256) must be 32 bytes long');

    });

});