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
import { OwnerSupportedKeyType } from "./types";

export class HcsDidCreateDidOwnerEvent extends HcsDidEvent {
    public readonly targetName = HcsDidEventTargetName.DID_OWNER;

    protected id: string;
    protected type: string; // Cryptographic key type (e.g., "Ed25519" or "Secp256k1")
    protected publicKeyFormat: OwnerSupportedKeyType; // Encoding/format of the public key (e.g., "EcdsaSecp256k1VerificationKey2020")
    protected controller: string;
    protected publicKey: PublicKey;

    constructor(id: string, controller: string, publicKey: PublicKey, publicKeyFormat?: string) {
        super();

        if (!id || !controller || !publicKey) {
            throw new DidError("Validation failed. DID Owner args are missing");
        }

        if (!this.isOwnerEventIdValid(id)) {
            throw new DidError("Event ID is invalid. Expected format: {did}#did-root-key");
        }

        this.id = id;
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
            (publicKeyFormat as OwnerSupportedKeyType) ||
            (this.type === "Ed25519" ? ED25519_KEY_TYPE : ECDSA_SECP256K1_KEY_TYPE);
    }

    public getId() {
        return this.id;
    }

    public getType() {
        return this.type;
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

    public getOwnerDef() {
        const publicKeyMultibase =
            this.publicKeyFormat === JSON_WEB_KEY_TYPE ? this.publicKey.toBytesRaw() : this.getPublicKeyMultibase();
        return generateDefinition(this.id, this.type, this.controller, publicKeyMultibase, this.publicKeyFormat);
    }

    public toJsonTree() {
        return { [this.targetName]: this.getOwnerDef() };
    }

    public toJSON() {
        return JSON.stringify(this.toJsonTree());
    }

    static fromJsonTree(tree: any): HcsDidCreateDidOwnerEvent {
        const { publicKey, publicKeyFormat } = parsePublicKey(tree);
        return new HcsDidCreateDidOwnerEvent(tree?.id, tree?.controller, publicKey, publicKeyFormat);
    }
}
