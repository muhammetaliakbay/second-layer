import {
    Content,
    DecodedPacket,
    DecryptedPacket,
    DeliveryType,
    PreSharedKey,
    PublicKey,
    SecondLayer,
    Signature,
    ValidatedPacket
} from "./second-layer";

import {createCipheriv, createDecipheriv, createECDH, createHash, createSign, createVerify, randomBytes} from 'crypto';

import {KeyStore} from "./key-store";

export class DecodeError extends Error {}

export class InvalidPacketLengthError extends DecodeError {}
export class InvalidMagicError extends DecodeError {}
export class InvalidStructureVersionError extends DecodeError {}
export class InvalidDeliveryTypeCodeError extends DecodeError {}

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

    decodePacket(raw: Buffer): DecodedPacket {
        if (raw.length < 4) {
            throw new InvalidPacketLengthError();
        } else if (!MAGIC.equals(raw.subarray(0, 4))) {
            throw new InvalidMagicError();
        }

        const signer = raw.subarray(4, 4 + 64);
        if (signer.length !== 64) {
            throw new InvalidPacketLengthError();
        }
        const decodedSigner: PublicKey = {
            x: signer.subarray(0, 32),
            y: signer.subarray(32, 64)
        };

        const signature = raw.subarray(4 + 64, 4 + 64 + 64);
        if (signature.length !== 64) {
            throw new InvalidPacketLengthError();
        }
        const decodedSignature: Signature = {
            r: signature.subarray(0, 32),
            s: signature.subarray(32, 64)
        };

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
            const target = content.subarray(2, 2 + 64);
            if (target.length !== 64) {
                throw new InvalidPacketLengthError();
            }

            decodedContent.target = {
                x: target.subarray(0, 32),
                y: target.subarray(32, 64)
            }

            decodedContent.payload = content.subarray(2 + 64);
        }

        return {
            rawContent: content,
            content: decodedContent,
            signer: decodedSigner,
            signature: decodedSignature,
            isDecoded: true,
        };
    }

    async validatePacket<C extends Content>(decodedPacket: DecodedPacket<C>): Promise<ValidatedPacket<C>> {
        let validated: boolean;

        try {
            const verify = createVerify('ecdsa-with-sha256');
            verify.update(decodedPacket.rawContent);
            validated = verify.verify(Buffer.concat([
                decodedPacket.signer.x,
                decodedPacket.signer.y
            ]), Buffer.concat([
                decodedPacket.signature.r,
                decodedPacket.signature.s
            ]));
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

    decryptPacket<C extends Content>(validatedPacket: ValidatedPacket<C>): DecryptedPacket<C> {
        let decryptedPayload: Buffer;

        if (validatedPacket.content.type === DeliveryType.PlainBroadcast) {

            decryptedPayload = validatedPacket.content.payload;

        } else if (validatedPacket.content.type === DeliveryType.EncryptedBroadcast) {

            const preSharedKey = this.keyStore.getPreSharedKey(
                validatedPacket.content.keyHash
            );
            if (preSharedKey == null) {
                throw new KeyNotFoundError();
            }

            const iv = validatedPacket.content.payload.subarray(0, 8);
            if (iv.length < 8) {
                throw new InvalidPacketLengthError();
            }

            const encrypted = validatedPacket.content.payload.subarray(8);

            const decipher = createDecipheriv('aes-256-cbc', preSharedKey, iv);

            decryptedPayload = Buffer.concat([
                decipher.update(encrypted),
                decipher.final()
            ]);

        } else if (validatedPacket.content.type === DeliveryType.Private) {

            const privateKey = this.keyStore.getPrivateKey(
                validatedPacket.content.target
            );
            if (privateKey == null) {
                throw new KeyNotFoundError();
            }

            const ecdh = createECDH('secp256k1');
            ecdh.setPrivateKey(privateKey);

            const secretKey = ecdh.computeSecret(Buffer.concat([
                validatedPacket.signer.x,
                validatedPacket.signer.y
            ]));

            const iv = validatedPacket.content.payload.subarray(0, 8);
            if (iv.length < 8) {
                throw new InvalidPacketLengthError();
            }

            const encrypted = validatedPacket.content.payload.subarray(8);

            const decipher = createDecipheriv('aes-256-cbc', secretKey, iv);

            decryptedPayload = Buffer.concat([
                decipher.update(encrypted),
                decipher.final()
            ]);

        }

        return {
            ...validatedPacket,
            decryptedPayload,
            isDecrypted: true
        };
    }

    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.PlainBroadcast): Buffer;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.EncryptedBroadcast, key: PreSharedKey): Buffer;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.Private, target: PublicKey): Buffer;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.PlainBroadcast | DeliveryType.EncryptedBroadcast | DeliveryType.Private, key?: PreSharedKey | PublicKey): Buffer {
        const privateKey = this.keyStore.getPrivateKey(signer);
        if (signer == null) {
            throw new KeyNotFoundError();
        }

        const deliveryCode = deliveryCodeByType[type];

        let typeSpecificBlock: Buffer;
        let payload: Buffer;

        if (type === DeliveryType.PlainBroadcast) {
            typeSpecificBlock = EMPTY_BUFFER;
        } else if (type === DeliveryType.EncryptedBroadcast) {
            const keyHash = createHash('sha256')
                .update((key as PreSharedKey))
                .digest();

            typeSpecificBlock = keyHash;

            const iv = randomBytes(8);
            const cipher = createCipheriv('aes-256-cbc', key as PreSharedKey, iv);
            const encrypted = Buffer.concat([
                cipher.update(plainPayload),
                cipher.final()
            ]);
            payload = Buffer.concat([
                iv,
                encrypted
            ]);
        } else if (type === DeliveryType.Private) {
            const ecdh = createECDH('secp256k1');
            ecdh.setPrivateKey(privateKey);

            const flatPublicKey = Buffer.concat([
                (key as PublicKey).x,
                (key as PublicKey).y
            ]);

            const secretKey = ecdh.computeSecret(flatPublicKey);

            typeSpecificBlock = flatPublicKey;

            const iv = randomBytes(8);
            const cipher = createCipheriv('aes-256-cbc', secretKey, iv);
            const encrypted = Buffer.concat([
                cipher.update(plainPayload),
                cipher.final()
            ]);
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

        const signBuffer = createSign('ecdsa-with-sha256')
            .update(content)
            .sign(privateKey);

        const signature: Signature = {
            r: signBuffer.subarray(0, 32),
            s: signBuffer.subarray(32, 64)
        };

        return Buffer.concat([
            MAGIC,
            Buffer.concat([signer.x, signer.y]),
            Buffer.concat([signature.r, signature.s]),
            content
        ]);
    }

}
