import { PublicKey } from "@hashgraph/sdk";
import {
    detectKeyTypeFromPublicKey,
    generateDefinition,
    getPublicKeyMultibaseString,
    parsePublicKey,
} from "../../../../../utils/crypto-utils";
import { DidError } from "../../../../did-error";
import { ECDSA_SECP256K1_KEY_TYPE, ED25519_KEY_TYPE, JSON_WEB_KEY_TYPE } from "../../hcs-did-key-type";
import { HcsDidEvent } from "../hcs-did-event";
import { HcsDidEventTargetName } from "../hcs-did-event-target-name";
import { VerificationRelationshipSupportedKeyType, VerificationRelationshipType } from "./types";

export class HcsDidCreateVerificationRelationshipEvent extends HcsDidEvent {
    public readonly targetName = HcsDidEventTargetName.VERIFICATION_RELATIONSHIP;

    protected id: string;
    protected type: string; // Cryptographic key type (e.g., "Ed25519" or "Secp256k1")
    protected publicKeyFormat: VerificationRelationshipSupportedKeyType; // Encoding/format of the public key (e.g., "EcdsaSecp256k1VerificationKey2020")
    protected relationshipType: VerificationRelationshipType;
    protected controller: string;
    protected publicKey: PublicKey;

    constructor(
        id: string,
        relationshipType: VerificationRelationshipType,
        controller: string,
        publicKey: PublicKey,
        publicKeyFormat?: string
    ) {
        super();

        if (!id || !relationshipType || !controller || !publicKey) {
            throw new DidError("Validation failed. Verification Relationship args are missing");
        }

        if (!this.isKeyEventIdValid(id)) {
            throw new DidError("Event ID is invalid. Expected format: {did}#key-{integer}");
        }

        this.id = id;
        this.relationshipType = relationshipType;
        this.controller = controller;
        this.publicKey = publicKey;

        const keyTypeFromPublicKey = detectKeyTypeFromPublicKey(this.publicKey);
        if (!keyTypeFromPublicKey) {
            throw new DidError("Unable to detect key type from public key");
        }
        this.type = keyTypeFromPublicKey;

        const validFormats = [ED25519_KEY_TYPE, ECDSA_SECP256K1_KEY_TYPE, JSON_WEB_KEY_TYPE];
        if (publicKeyFormat && !validFormats.includes(publicKeyFormat)) {
            throw new DidError(`Unsupported public key format: ${publicKeyFormat}`);
        }

        this.publicKeyFormat =
            (publicKeyFormat as VerificationRelationshipSupportedKeyType) ||
            (this.type === "Ed25519" ? ED25519_KEY_TYPE : ECDSA_SECP256K1_KEY_TYPE);
    }

    public getId() {
        return this.id;
    }

    public getType() {
        return this.type;
    }

    public getRelationshipType() {
        return this.relationshipType;
    }

    public getController() {
        return this.controller;
    }

    public getPublicKey() {
        return this.publicKey;
    }

    public getPublicKeyFormat() {
        return this.publicKeyFormat;
    }

    public getPublicKeyMultibase() {
        if (this.publicKeyFormat === JSON_WEB_KEY_TYPE) {
            throw new DidError("Public key format is JsonWebKey2020 and does not support multibase encoding");
        }
        const publicKeyBytes = this.publicKey.toBytesRaw();
        return getPublicKeyMultibaseString(this.publicKeyFormat, publicKeyBytes);
    }

    public getVerificationRelationshipDef() {
        const publicKeyMultibase =
            this.publicKeyFormat === JSON_WEB_KEY_TYPE ? this.publicKey.toBytesRaw() : this.getPublicKeyMultibase();
        return generateVerificationRelationshipDefinition(
            this.id,
            this.type,
            this.controller,
            publicKeyMultibase,
            this.publicKeyFormat,
            this.relationshipType
        );
    }

    public toJsonTree() {
        return { [this.targetName]: this.getVerificationRelationshipDef() };
    }

    public toJSON() {
        return JSON.stringify(this.toJsonTree());
    }

    static fromJsonTree(tree: any): HcsDidCreateVerificationRelationshipEvent {
        const { publicKey, publicKeyFormat } = parsePublicKey(tree);
        return new HcsDidCreateVerificationRelationshipEvent(
            tree?.id,
            tree?.relationshipType,
            tree?.controller,
            publicKey,
            publicKeyFormat
        );
    }
}

/**
 * Generate the owner definition based on the key type and relationship type.
 */
function generateVerificationRelationshipDefinition(
    id: string,
    type: string,
    controller: string,
    publicKeyMultibaseOrBytes: string | Uint8Array,
    publicKeyFormat: VerificationRelationshipSupportedKeyType,
    relationshipType?: VerificationRelationshipType
) {
    const baseDefinition = generateDefinition(id, type, controller, publicKeyMultibaseOrBytes, publicKeyFormat);

    if (relationshipType) {
        return {
            ...baseDefinition,
            relationshipType,
        };
    }
    return baseDefinition;
}
