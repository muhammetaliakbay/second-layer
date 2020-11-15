import {createPrivateKey, createSecretKey, KeyStoreImpl} from "./key-store-impl";
import {SecondLayerImpl} from "./second-layer-impl";
import {DeliveryType} from "./second-layer";
import { assert } from "chai";
import {Hash, PrivateKey, PublicKey, SecretKey} from "./key-store";

describe('SecondLayer tests', async () => {

    const keyStore = new KeyStoreImpl();
    const secondLayer = new SecondLayerImpl(keyStore);

    const plainData = Buffer.from('Hello World!', 'utf8');

    let privateKey: PrivateKey;
    let publicKey: PublicKey;

    before(async () => {
        privateKey = await createPrivateKey();
        publicKey = await privateKey.getPublicKey();
        await keyStore.putPrivateKey(privateKey);
    });

    it('encode PlainBroadcast packet', async () => {

        await secondLayer.encodePacket(plainData, publicKey, DeliveryType.PlainBroadcast);

    });

    it('decode PlainBroadcast packet', async () => {

        const packet = await secondLayer.encodePacket(plainData, publicKey, DeliveryType.PlainBroadcast);

        const decodedPacket = await secondLayer.decodePacket(packet);

        assert(await decodedPacket.signer.equals(publicKey), 'Signer public key in packet must be equals to public-key');

        const validatedPacket = await secondLayer.validatePacket(decodedPacket);
        const decryptedPacket = await secondLayer.decryptPacket(validatedPacket);

        assert(plainData.equals(decryptedPacket.decryptedPayload), 'Source data and decoded data must be equals');

    });

    let secretKey: SecretKey;
    let secretKeyHash: Hash;

    before(async () => {
        secretKey = await createSecretKey();
        secretKeyHash = await secretKey.getHash();
        await keyStore.putSecretKey(secretKey);
    });

    it('encode EncryptedBroadcast packet', async () => {

        await secondLayer.encodePacket(plainData, publicKey, DeliveryType.EncryptedBroadcast, secretKeyHash);

    });

    it('decode EncryptedBroadcast packet', async () => {

        const packet = await secondLayer.encodePacket(plainData, publicKey, DeliveryType.EncryptedBroadcast, secretKeyHash);

        const decodedPacket = await secondLayer.decodePacket(packet);

        assert(await decodedPacket.signer.equals(publicKey), 'Signer public key in packet must be equals to public-key');
        assert(decodedPacket.content.keyHash.equals(secretKeyHash), 'SecretKey Hash in packet must be equals to hash of secret-key');

        const validatedPacket = await secondLayer.validatePacket(decodedPacket);
        const decryptedPacket = await secondLayer.decryptPacket(validatedPacket);

        assert(plainData.equals(decryptedPacket.decryptedPayload), 'Source data and decoded data must be equals');

    });

    let targetPrivate: PrivateKey;
    let target: PublicKey;

    before(async () => {
        targetPrivate = await createPrivateKey();
        target = await targetPrivate.getPublicKey();
        await keyStore.putPrivateKey(targetPrivate);
    });

    it('encode Private packet', async () => {

        const packet = await secondLayer.encodePacket(plainData, publicKey, DeliveryType.Private, target);

        assert(packet.subarray(4, 4 + 64).equals(await publicKey.getBytes()), 'Signer public key data in packet must be equals to bytes of public-key');
        assert(packet.subarray(4 + 64 + 64 + 2, 4 + 64 + 64 + 2 + 64).equals(await target.getBytes()), 'Target public key data in packet must be equals to bytes of target-public-key');

    });

    it('decode Private packet', async () => {

        const packet = await secondLayer.encodePacket(plainData, publicKey, DeliveryType.Private, target);

        const decodedPacket = await secondLayer.decodePacket(packet);

        assert(await decodedPacket.signer.equals(publicKey), 'Signer public key in packet must be equals to public-key');
        assert(await decodedPacket.content.target.equals(target), 'Target public key in packet must be equals to target-public-key');

        const validatedPacket = await secondLayer.validatePacket(decodedPacket);
        const decryptedPacket = await secondLayer.decryptPacket(validatedPacket);

        assert(plainData.equals(decryptedPacket.decryptedPayload), 'Source data and decoded data must be equals');

    });

});