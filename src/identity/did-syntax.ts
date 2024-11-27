export namespace DidSyntax {
    export const DID_PREFIX = "did";
    export const DID_DOCUMENT_CONTEXT = "https://www.w3.org/ns/did/v1";
    export const DID_VERIFICATION_METHOD_CONTEXTS: Record<string, string> = {
        JsonWebKey2020: "https://w3id.org/security/suites/jws-2020/v1",
        Ed25519: "https://w3id.org/security/suites/ed25519-2020/v1",
        Secp256k1: "https://w3id.org/security/suites/secp256k1-2020/v1",
    };
    export const DID_METHOD_SEPARATOR = ":";
    export const DID_TOPIC_SEPARATOR = "_";
    export const HEDERA_NETWORK_MAINNET = "mainnet";
    export const HEDERA_NETWORK_TESTNET = "testnet";
    export const HEDERA_NETWORK_PREVIEWNET = "previewnet";

    export enum Method {
        HEDERA_HCS = "hedera",
    }
}

export const DEFAULT_HEDERA_MIRRORNODES: Record<string, string> = {
    [DidSyntax.HEDERA_NETWORK_MAINNET]: "https://mainnet-public.mirrornode.hedera.com",
    [DidSyntax.HEDERA_NETWORK_TESTNET]: "https://testnet.mirrornode.hedera.com",
    [DidSyntax.HEDERA_NETWORK_PREVIEWNET]: "https://previewnet.mirrornode.hedera.com",
};
