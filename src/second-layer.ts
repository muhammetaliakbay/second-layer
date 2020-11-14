import {KeyStore} from "./key-store";

export type Hash = Buffer;
export type KeyHash = Hash;
export type PreSharedKey = Buffer;
export interface PublicKey {
    x: Buffer;
    y: Buffer;
}
export type PrivateKey = Buffer;
export interface Signature {
    r: Buffer,
    s: Buffer
}

export interface RawPacket<C extends Content = Content> {
    rawContent: Buffer;
    signer: PublicKey;
    signature: Signature;
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
    keyHash?: KeyHash;
    target?: PublicKey;
}

export interface PlainBroadcastContent extends BaseContent {
    type: DeliveryType.PlainBroadcast;
}

export interface EncryptedBroadcastContent extends BaseContent {
    type: DeliveryType.EncryptedBroadcast;
    keyHash: KeyHash;
}

export interface PrivateContent extends BaseContent {
    type: DeliveryType.Private;
    target: PublicKey;
}

export type Content = PlainBroadcastContent | EncryptedBroadcastContent | PrivateContent;

export interface SecondLayer {
    getKeyStore(): KeyStore;

    decodePacket(raw: Buffer): DecodedPacket;
    validatePacket<C extends Content>(decodedPacket: DecodedPacket<C>): Promise<ValidatedPacket<C>>;
    decryptPacket<C extends Content>(validatedPacket: ValidatedPacket<C>): DecryptedPacket<C>;

    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.PlainBroadcast): Buffer;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.EncryptedBroadcast, key: PreSharedKey): Buffer;
    encodePacket(plainPayload: Buffer, signer: PublicKey, type: DeliveryType.Private, target: PublicKey): Buffer;
}
