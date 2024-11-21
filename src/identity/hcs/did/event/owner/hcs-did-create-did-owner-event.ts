import { PublicKey } from "@hashgraph/sdk";
import { Hashing } from "../../../../../utils/hashing";
import { DidError } from "../../../../did-error";
import { HcsDidEvent } from "../hcs-did-event";
import { HcsDidEventTargetName } from "../hcs-did-event-target-name";

export class HcsDidCreateDidOwnerEvent extends HcsDidEvent {
    public static ECDSA_SECP256K1_KEY_TYPE = "EcdsaSecp256k1VerificationKey2019";
    public static ED25519_KEY_TYPE = "Ed25519VerificationKey2018";

    public readonly targetName = HcsDidEventTargetName.DID_OWNER;

    protected id: string;
    protected type = HcsDidCreateDidOwnerEvent.ED25519_KEY_TYPE;
    protected controller: string;
    protected publicKey: PublicKey;

    constructor(id: string, controller: string, publicKey: PublicKey, privateKeyCurve?: string) {
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
        if (privateKeyCurve === "Secp256k1") {
            this.type = HcsDidCreateDidOwnerEvent.ECDSA_SECP256K1_KEY_TYPE;
        } else if (privateKeyCurve === "Ed25519") {
            this.type = HcsDidCreateDidOwnerEvent.ED25519_KEY_TYPE;
        } else {
            throw new DidError(`Invalid private key curve: ${privateKeyCurve}`);
        }
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

    public getPublicKeyBase58() {
        return Hashing.base58.encode(this.getPublicKey().toBytes());
    }

    public getOwnerDef() {
        return {
            id: this.getId(),
            type: this.getType(),
            controller: this.getController(),
            publicKeyBase58: this.getPublicKeyBase58(),
        };
    }

    public toJsonTree() {
        return {
            [this.targetName]: {
                id: this.getId(),
                type: this.getType(),
                controller: this.getController(),
                publicKeyBase58: this.getPublicKeyBase58(),
            },
        };
    }

    public toJSON() {
        return JSON.stringify(this.toJsonTree());
    }

    static fromJsonTree(tree: any): HcsDidCreateDidOwnerEvent {
        const publicKey = PublicKey.fromBytes(Hashing.base58.decode(tree?.publicKeyBase58));
        const type = tree?.type || HcsDidCreateDidOwnerEvent.ED25519_KEY_TYPE; // Default to Ed25519 if type is missing
        const privateKeyCurve = type === HcsDidCreateDidOwnerEvent.ECDSA_SECP256K1_KEY_TYPE ? "Secp256k1" : "Ed25519";

        return new HcsDidCreateDidOwnerEvent(tree?.id, tree?.controller, publicKey, privateKeyCurve);
    }
}
