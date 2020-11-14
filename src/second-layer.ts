import {Hash, KeyStore, PublicKey, SecretKey} from "./key-store";

export interface RawPacket<C extends Content = Content> {
    rawContent: Buffer;
    signer: PublicKey;
    signature: Buffer;
}

export interface DecodedPacket<C extends Content = Content> extends RawPacket<C> {
    isDecoded: true;
    content: C;
}

export interface ValidatedPacket<C extends Content = Content> extends DecodedPacket<C> {
    isValidated: true;
}

export interface DecryptedPacket<C extends Content = Content> extends ValidatedPacket<C> {
    isDecrypted: true;
    decryptedPayload: Buffer;
}

export enum DeliveryType {
    PlainBroadcast = 'plain-broadcast',
    EncryptedBroadcast = 'encrypted-broadcast',
    Private = 'private'
}

export interface BaseContent {
    type: DeliveryType;
    payload: Buffer;
    keyHash?: Hash;
    target?: PublicKey;
}

export interface PlainBroadcastContent extends BaseContent {
    type: DeliveryType.PlainBroadcast;
}

export interface EncryptedBroadcastContent extends BaseContent {
    type: DeliveryType.EncryptedBroadcast;
    keyHash: Hash;
}

export interface PrivateContent extends BaseContent {
    type: DeliveryType.Private;
    target: PublicKey;
}

export type Content = PlainBroadcastContent | EncryptedBroadcastContent | PrivateContent;

export interface SecondLayer {
    getKeyStore(): KeyStore;

    decodePacket(raw: Buffer): Promise<DecodedPacket>;
    validatePacket<C extends Content>(decodedPacket: DecodedPacket<C>): Promise<ValidatedPacket<C>>;
    decryptPacket<C extends Content>(validatedPacket: ValidatedPacket<C>): Promise<DecryptedPacket<C>>;

    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.PlainBroadcast): Promise<Buffer>;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.EncryptedBroadcast, key: SecretKey): Promise<Buffer>;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.Private, target: PublicKey): Promise<Buffer>;
}
