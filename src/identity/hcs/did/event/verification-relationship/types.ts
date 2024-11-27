import { ECDSA_SECP256K1_KEY_TYPE, ED25519_KEY_TYPE, JSON_WEB_KEY_TYPE } from "../../hcs-did-key-type";

export type VerificationRelationshipType =
    | "authentication"
    | "assertionMethod"
    | "keyAgreement"
    | "capabilityInvocation"
    | "capabilityDelegation";

export type VerificationRelationshipSupportedKeyType =
    | typeof ECDSA_SECP256K1_KEY_TYPE
    | typeof ED25519_KEY_TYPE
    | typeof JSON_WEB_KEY_TYPE;
