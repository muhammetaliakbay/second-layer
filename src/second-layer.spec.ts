import {expect} from "chai";
import {createPrivateKey, createSecretKey, KeyStoreImpl} from "./key-store-impl";
import {SecondLayerImpl} from "./second-layer-impl";
import {DeliveryType} from "./second-layer";

describe('SecondLayer tests', async () => {

    const keyStore = new KeyStoreImpl();
    const secondLayer = new SecondLayerImpl(keyStore);

    const plainData = Buffer.from('Hello World!', 'utf8');
    const privateKey = await createPrivateKey();
    const publicKey = await privateKey.getPublicKey();

    await keyStore.putPrivateKey(privateKey);

    it('encode PlainBroadcast packet', async () => {

        await secondLayer.encodePacket(plainData, publicKey, DeliveryType.PlainBroadcast);

    });

    const secretKey = await createSecretKey();

    it('encode EncryptedBroadcast packet', async () => {

        await secondLayer.encodePacket(plainData, publicKey, DeliveryType.EncryptedBroadcast, secretKey);

    });

    const targetPrivate = await createPrivateKey();
    const target = await targetPrivate.getPublicKey();

    it('encode Private packet', async () => {

        await secondLayer.encodePacket(plainData, publicKey, DeliveryType.Private, target);

    });

});