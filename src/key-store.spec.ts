import { assert, expect } from "chai";
import {createPrivateKey, createSecretKey} from "./key-store-impl";
import {crypto} from "./crypto";

describe('KeyStore tests', () => {

    it('checking secret-key', async () => {

        const secretKey = await createSecretKey();

        const keyRaw = await secretKey.getBytes();
        expect(keyRaw.length).equals(32, 'Secret Key (AES-256) must be 32 bytes long');

        const keyHash = await secretKey.getBytes();
        expect(keyHash.length).equals(32, 'Secret Key\'s Hash (SHA-256) must be 32 bytes long');

    });

    it('checking ec-key', async () => {

        const privateKey = await createPrivateKey();

        const keyRaw = await privateKey.getBytes();
        expect(keyRaw.length).equals(32, 'Private Key (EC-256) must be 32 bytes long');

        const publicKey = await privateKey.getPublicKey();

        const pubRaw = await publicKey.getBytes();
        expect(pubRaw.length).equals(64, 'Public Key (EC-256) must be 64 bytes long (32 bytes x, 32 bytes y)');

    });

});