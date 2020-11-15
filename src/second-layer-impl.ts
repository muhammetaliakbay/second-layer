import {
    Content,
    DecodedPacket,
    DecryptedPacket,
    DeliveryType,
    SecondLayer,
    ValidatedPacket
} from "./second-layer";

import {KeyStore, PublicKey, SecretKey} from "./key-store";
import {importPublicKey, importPublicKeyXY, PublicKeyImpl} from "./key-store-impl";

import {crypto, EC256_CURVE} from './crypto';

export class DecodeError extends Error {}

export class InvalidPacketLengthError extends DecodeError {}
export class InvalidMagicError extends DecodeError {}
export class InvalidStructureVersionError extends DecodeError {}
export class InvalidDeliveryTypeCodeError extends DecodeError {}
export class InvalidPublicKeyError extends DecodeError {}

export class ValidationFailedError extends DecodeError {
    constructor(reason?: any) {
        super(reason);
    }
}

export class KeyNotFoundError extends DecodeError {}

const deliveryTypeByCode = [
    DeliveryType.PlainBroadcast,
    DeliveryType.EncryptedBroadcast,
    DeliveryType.Private
] as const;

const deliveryCodeByType = {
    [DeliveryType.PlainBroadcast]: 0,
    [DeliveryType.EncryptedBroadcast]: 1,
    [DeliveryType.Private]: 2
};

const EMPTY_BUFFER = Buffer.alloc(0);
const MAGIC = Buffer.from('\x00#2L', 'ascii');

export class SecondLayerImpl implements SecondLayer {

    constructor(
        private keyStore: KeyStore
    ) {
    }

    getKeyStore(): KeyStore {
        return this.keyStore;
    }

    async decodePacket(raw: Buffer): Promise<DecodedPacket> {
        if (raw.length < 4) {
            throw new InvalidPacketLengthError();
        } else if (!MAGIC.equals(raw.subarray(0, 4))) {
            throw new InvalidMagicError();
        }

        const signer = raw.subarray(4, 4 + 64);
        if (signer.length !== 64) {
            throw new InvalidPacketLengthError();
        }

        const signerPub: PublicKey = await importPublicKeyXY(signer);

        const signature = raw.subarray(4 + 64, 4 + 64 + 64);
        if (signature.length !== 64) {
            throw new InvalidPacketLengthError();
        }

        const content = raw.subarray(4 + 64 + 64);
        if (content.length < 2) {
            throw new InvalidPacketLengthError();
        }

        const structureVersion = content.readUInt8(0);
        if (structureVersion !== 0) {
            throw new InvalidStructureVersionError();
        }

        const deliveryTypeCode = content.readUInt8(1);
        const deliveryType = deliveryTypeByCode[deliveryTypeCode];
        if (deliveryType == null) {
            throw new InvalidDeliveryTypeCodeError();
        }

        const decodedContent = {
            type: deliveryType
        } as Content;

        if (deliveryType === DeliveryType.PlainBroadcast) {
            decodedContent.payload = content.subarray(2);
        } else if (deliveryType === DeliveryType.EncryptedBroadcast) {
            decodedContent.keyHash = content.subarray(2, 2 + 32);
            if (decodedContent.keyHash.length !== 32) {
                throw new InvalidPacketLengthError();
            }

            decodedContent.payload = content.subarray(2 + 32);
        } else if (deliveryType === DeliveryType.Private) {
            const target = content.subarray(0, 64);
            if (target.length !== 64) {
                throw new InvalidPacketLengthError();
            }

            decodedContent.target = await importPublicKeyXY(target);

            decodedContent.payload = content.subarray(2 + 64);
        }

        return {
            rawContent: content,
            content: decodedContent,
            signer: signerPub,
            signature,
            isDecoded: true,
        };
    }

    async validatePacket<C extends Content>(decodedPacket: DecodedPacket<C>): Promise<ValidatedPacket<C>> {
        let validated: boolean;

        try {
            validated = await crypto.subtle.verify({
                name: 'ECDSA',
                hash: 'SHA-256'
            }, await decodedPacket.signer.getCryptoKey('ECDSA'), decodedPacket.signature, decodedPacket.rawContent);
        } catch (e) {
            throw new ValidationFailedError(e);
        }

        if (validated !== true) {
            throw new ValidationFailedError();
        }

        return {
            ...decodedPacket,
            isValidated: true
        };
    }

    async decryptPacket<C extends Content>(validatedPacket: ValidatedPacket<C>): Promise<DecryptedPacket<C>> {
        let decryptedPayload: Buffer;

        if (validatedPacket.content.type === DeliveryType.PlainBroadcast) {

            decryptedPayload = validatedPacket.content.payload;

        } else if (validatedPacket.content.type === DeliveryType.EncryptedBroadcast) {

            const preSharedKey = await this.keyStore.getSecretKey(
                validatedPacket.content.keyHash
            );
            if (preSharedKey == null) {
                throw new KeyNotFoundError();
            }

            const iv = validatedPacket.content.payload.subarray(0, 16);
            if (iv.length < 16) {
                throw new InvalidPacketLengthError();
            }

            const encrypted = validatedPacket.content.payload.subarray(16);

            decryptedPayload = Buffer.from(
                await crypto.subtle.decrypt(
                    {
                        name: 'AES-CBC',
                        iv
                    },
                    await preSharedKey.getCryptoKey('AES'),
                    encrypted
                )
            );

        } else if (validatedPacket.content.type === DeliveryType.Private) {

            const privateKey = await this.keyStore.getPrivateKey(
                validatedPacket.content.target
            );
            if (privateKey == null) {
                throw new KeyNotFoundError();
            }

            const secretKey = await this.keyStore.deriveKey(
                validatedPacket.signer, privateKey
            );

            const iv = validatedPacket.content.payload.subarray(0, 16);
            if (iv.length < 16) {
                throw new InvalidPacketLengthError();
            }

            const encrypted = validatedPacket.content.payload.subarray(16);

            decryptedPayload = Buffer.from(
                await crypto.subtle.decrypt(
                    {
                        name: 'AES-CBC',
                        iv
                    }, secretKey, encrypted
                )
            );

        }

        return {
            ...validatedPacket,
            decryptedPayload,
            isDecrypted: true
        };
    }

    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.PlainBroadcast): Promise<Buffer>;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.EncryptedBroadcast, key: SecretKey): Promise<Buffer>;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.Private, target: PublicKey): Promise<Buffer>;
    async encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.PlainBroadcast | DeliveryType.EncryptedBroadcast | DeliveryType.Private, key?: SecretKey | PublicKey): Promise<Buffer> {
        const privateKey = await this.keyStore.getPrivateKey(signer);
        if (privateKey == null) {
            throw new KeyNotFoundError();
        }

        const deliveryCode = deliveryCodeByType[type];

        let typeSpecificBlock: Buffer;
        let payload: Buffer;

        if (type === DeliveryType.PlainBroadcast) {
            typeSpecificBlock = EMPTY_BUFFER;
            payload = plainPayload;
        } else if (type === DeliveryType.EncryptedBroadcast) {
            const keyHash = await key.getHash();

            typeSpecificBlock = keyHash;

            const iv = crypto.getRandomValues(new Uint8Array(16));
            const encrypted = Buffer.from(await crypto.subtle.encrypt(
                {
                    name: 'AES-CBC',
                    iv
                }, await (key as SecretKey).getCryptoKey('AES'), plainPayload
            ));
            payload = Buffer.concat([
                iv,
                encrypted
            ]);
        } else if (type === DeliveryType.Private) {
            const secretKey = await this.keyStore.deriveKey(key as PublicKey, privateKey);

            const targetBytes = await key.getBytes();

            typeSpecificBlock = Buffer.from(targetBytes);

            const iv = crypto.getRandomValues(new Uint8Array(16));
            const encrypted = Buffer.from(
                await crypto.subtle.encrypt(
                    {
                        name: 'AES-CBC',
                        iv
                    }, await secretKey.getCryptoKey('AES'), plainPayload
                )
            );
            payload = Buffer.concat([
                iv,
                encrypted
            ]);
        }

        const contentHeader = Buffer.alloc(2);
        contentHeader.writeUInt8(0, 0);
        contentHeader.writeUInt8(deliveryCode, 1);

        const content = Buffer.concat([
            contentHeader,
            typeSpecificBlock,
            payload
        ]);

        const signerBytes = await signer.getBytes();

        const signature = Buffer.from(
            await crypto.subtle.sign(
                {
                    name: 'ECDSA',
                    hash: 'SHA-256'
                }, await privateKey.getCryptoKey('ECDSA'), content
            )
        );

        return Buffer.concat([
            MAGIC,
            signerBytes,
            signature,
            content
        ]);
    }

}
