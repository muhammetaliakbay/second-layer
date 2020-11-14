import {
    Content,
    DecodedPacket,
    DecryptedPacket,
    DeliveryType,
    PreSharedKey,
    PublicKey,
    SecondLayer,
    ValidatedPacket
} from "./second-layer";

import {createDecipheriv} from 'crypto';

import {Keccak} from 'sha3';

import {verify} from 'eccrypto';
import {KeyStore} from "./key-store";

export class DecodeError extends Error {}

export class InvalidPacketLengthError extends DecodeError {}
export class InvalidMagicError extends DecodeError {}
export class InvalidStructureVersionError extends DecodeError {}
export class InvalidDeliveryTypeCodeError extends DecodeError {}

export class ValidationFailedError extends DecodeError {}

export class KeyNotFoundError extends DecodeError {}

const deliveryTypeByCode = [
    DeliveryType.PlainBroadcast,
    DeliveryType.EncryptedBroadcast,
    DeliveryType.Private
] as const;

export class SecondLayerImpl implements SecondLayer {
    private static magic = Buffer.from('\x00#2L', 'ascii');

    constructor(
        private keyStore: KeyStore
    ) {
    }

    getKeyStore(): KeyStore {
        return this.keyStore;
    }

    decodePacket(raw: Buffer): DecodedPacket {
        if (raw.length < 4) {
            throw new InvalidPacketLengthError();
        } else if (!SecondLayerImpl.magic.equals(raw.subarray(0, 4))) {
            throw new InvalidMagicError();
        }

        const signer = raw.subarray(4, 4 + 64);
        if (signer.length !== 64) {
            throw new InvalidPacketLengthError();
        }

        const signature = raw.subarray(4 + 64, 4 + 64 + 65);
        if (signature.length !== 65) {
            throw new InvalidPacketLengthError();
        }
        const content = raw.subarray(4 + 64 + 65);

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
            decodedContent.target = content.subarray(2, 2 + 32);
            if (decodedContent.target.length !== 32) {
                throw new InvalidPacketLengthError();
            }
            decodedContent.payload = content.subarray(2 + 32);
        }

        return {
            rawContent: content,
            content: decodedContent,
            signature,
            signer,
            isDecoded: true,
        };
    }

    async validatePacket<C extends Content>(decodedPacket: DecodedPacket<C>): Promise<ValidatedPacket<C>> {
        const contentHash = new Keccak(256).update(decodedPacket.rawContent).digest();

        try {
            await verify(decodedPacket.signer, contentHash, decodedPacket.signature);
        } catch (e) {
            throw new ValidationFailedError();
        }

        return {
            ...decodedPacket,
            contentHash,
            isValidated: true
        };
    }

    decryptPacket<C extends Content>(validatedPacket: ValidatedPacket<C>): DecryptedPacket<C> {
        let decryptedPayload: Buffer;

        if (validatedPacket.content.type === DeliveryType.PlainBroadcast) {
            decryptedPayload = validatedPacket.content.payload;
        } else if (validatedPacket.content.type === DeliveryType.EncryptedBroadcast) {
            const key = this.keyStore.getPreShareKey(
                validatedPacket.content.keyHash
            );
            if (key == null) {
                throw new KeyNotFoundError();
            }

            const iv = validatedPacket.content.payload.subarray(0, 8);
            if (iv.length < 8) {
                throw new InvalidPacketLengthError();
            }

            const encrypted = validatedPacket.content.payload.subarray(8);

            const decipher = createDecipheriv('aes-256-cbc', key, iv);

            decryptedPayload = Buffer.concat([
                decipher.update(encrypted),
                decipher.final()
            ]);
        } else if (validatedPacket.content.type === DeliveryType.Private) {

        }

        return {
            ...validatedPacket,
            decryptedPayload,
            isDecrypted: true
        };
    }

    encodePacket(plainPayload: Buffer, type: DeliveryType.PlainBroadcast): Buffer;
    encodePacket(plainPayload: Buffer, type: DeliveryType.EncryptedBroadcast, key: PreSharedKey): Buffer;
    encodePacket(plainPayload: Buffer, type: DeliveryType.Private, target: PublicKey): Buffer;
    encodePacket(plainPayload: Buffer, type: DeliveryType.PlainBroadcast | DeliveryType.EncryptedBroadcast | DeliveryType.Private, key?: PreSharedKey | PublicKey): Buffer {

    }

}
