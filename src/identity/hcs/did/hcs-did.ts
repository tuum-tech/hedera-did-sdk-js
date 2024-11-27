import {
    Client,
    Hbar,
    PrivateKey,
    PublicKey,
    Timestamp,
    TopicCreateTransaction,
    TopicId,
    TopicUpdateTransaction,
    TransactionId,
} from "@hashgraph/sdk";
import { base58btc } from "multiformats/bases/base58";
import {
    detectKeyTypeFromIdentifier,
    detectKeyTypeFromPublicKey,
    getPublicKeyBase58ForEd25519,
    getPublicKeyBase58ForSecp256k1,
    isValidCompressedOrUncompressedSecp256k1Key,
    MULTICODECS,
    removeMulticodecPrefix,
} from "../../../utils/crypto-utils";
import { DidDocument } from "../../did-document";
import { DidError, DidErrorCode } from "../../did-error";
import { DidMethodOperation } from "../../did-method-operation";
import { DEFAULT_HEDERA_MIRRORNODES, DidSyntax } from "../../did-syntax";
import { MessageEnvelope } from "../message-envelope";
import { HcsDidDeleteEvent } from "./event/document/hcs-did-delete-event";
import { HcsDidEvent } from "./event/hcs-did-event";
import { HcsDidCreateDidOwnerEvent } from "./event/owner/hcs-did-create-did-owner-event";
import { HcsDidUpdateDidOwnerEvent } from "./event/owner/hcs-did-update-did-owner-event";
import { OwnerSupportedKeyType } from "./event/owner/types";
import { HcsDidCreateServiceEvent } from "./event/service/hcs-did-create-service-event";
import { HcsDidRevokeServiceEvent } from "./event/service/hcs-did-revoke-service-event";
import { HcsDidUpdateServiceEvent } from "./event/service/hcs-did-update-service-event";
import { ServiceTypes } from "./event/service/types";
import { HcsDidCreateVerificationMethodEvent } from "./event/verification-method/hcs-did-create-verification-method-event";
import { HcsDidRevokeVerificationMethodEvent } from "./event/verification-method/hcs-did-revoke-verification-method-event";
import { HcsDidUpdateVerificationMethodEvent } from "./event/verification-method/hcs-did-update-verification-method-event";
import { VerificationMethodSupportedKeyType } from "./event/verification-method/types";
import { HcsDidCreateVerificationRelationshipEvent } from "./event/verification-relationship/hcs-did-create-verification-relationship-event";
import { HcsDidRevokeVerificationRelationshipEvent } from "./event/verification-relationship/hcs-did-revoke-verification-relationship-event";
import { HcsDidUpdateVerificationRelationshipEvent } from "./event/verification-relationship/hcs-did-update-verification-relationship-event";
import {
    VerificationRelationshipSupportedKeyType,
    VerificationRelationshipType,
} from "./event/verification-relationship/types";
import { HcsDidEventMessageResolver } from "./hcs-did-event-message-resolver";
import { ECDSA_SECP256K1_KEY_TYPE, ED25519_KEY_TYPE, JSON_WEB_KEY_TYPE } from "./hcs-did-key-type";
import { HcsDidMessage } from "./hcs-did-message";
import { HcsDidTransaction } from "./hcs-did-transaction";

export class HcsDid {
    public static DID_METHOD = DidSyntax.Method.HEDERA_HCS;
    public static TRANSACTION_FEE = new Hbar(2);
    public static READ_TOPIC_MESSAGES_TIMEOUT = 5000;

    protected client?: Client;
    protected privateKey?: PrivateKey;
    protected keyType: string = "Ed25519"; // Or 'Secp256k1';
    protected publicKeyFormat = ED25519_KEY_TYPE;
    protected identifier?: string;
    protected network?: string = DidSyntax.HEDERA_NETWORK_MAINNET;
    protected mirrorNodeUrl?: string = DEFAULT_HEDERA_MIRRORNODES[DidSyntax.HEDERA_NETWORK_MAINNET];
    protected topicId: TopicId | undefined | null;

    protected messages: HcsDidMessage[] = [];
    protected resolvedAt: Timestamp = Timestamp.generate();
    protected document?: DidDocument;

    constructor(args: {
        network?: string;
        identifier?: string;
        privateKey?: PrivateKey;
        publicKeyFormat?: string;
        client?: Client;
    }) {
        this.network = args.network || this.network;
        if (this.network) {
            this.mirrorNodeUrl = DEFAULT_HEDERA_MIRRORNODES[this.network];
        }
        this.identifier = args.identifier;
        this.privateKey = args.privateKey;
        if (this.privateKey) {
            const keyTypeFromPrivateKey = detectKeyTypeFromPublicKey(this.privateKey.publicKey);
            if (!keyTypeFromPrivateKey) {
                throw new DidError("Unable to detect key type from private key");
            }
            this.keyType = keyTypeFromPrivateKey;
        }

        this.client = args.client;

        if (!this.identifier && !this.privateKey) {
            throw new DidError("identifier and privateKey cannot both be empty");
        }

        if (this.identifier) {
            const [networkName, topicId] = HcsDid.parseIdentifier(this.identifier);
            this.network = networkName;
            this.topicId = topicId;
            this.mirrorNodeUrl = DEFAULT_HEDERA_MIRRORNODES[this.network];
            // Automatically detect the curve type from the identifier
            const keyTypeFromIdentifier = detectKeyTypeFromIdentifier(this.identifier);
            if (!keyTypeFromIdentifier) {
                throw new DidError("Unable to detect key type from identifier");
            }
            this.keyType = keyTypeFromIdentifier;
        }

        if (this.keyType === "Ed25519") {
            this.publicKeyFormat = ED25519_KEY_TYPE;
        } else if (this.keyType === "Secp256k1") {
            this.publicKeyFormat = ECDSA_SECP256K1_KEY_TYPE;
        } else {
            this.publicKeyFormat = JSON_WEB_KEY_TYPE;
        }

        if (args.publicKeyFormat) {
            this.publicKeyFormat = args.publicKeyFormat as OwnerSupportedKeyType;
        }
    }

    /**
     * Public API
     */

    public async register() {
        this.validateClientConfig();

        if (this.identifier) {
            await this.resolve();

            if (this.document!.hasOwner()) {
                throw new DidError("DID is already registered");
            }
        } else {
            /**
             * Create topic
             */
            const topicCreateTransaction = new TopicCreateTransaction()
                .setMaxTransactionFee(HcsDid.TRANSACTION_FEE)
                .setAdminKey(this.privateKey!.publicKey)
                .setSubmitKey(this.privateKey!.publicKey)
                .freezeWith(this.client!);

            const sigTx = await topicCreateTransaction.sign(this.privateKey!);
            const txId = await sigTx.execute(this.client!);
            const topicId = (await txId.getReceipt(this.client!)).topicId;

            this.topicId = topicId;
            this.identifier = this.buildIdentifier(this.privateKey!.publicKey);
        }

        /**
         * Set ownership
         */
        const event = new HcsDidCreateDidOwnerEvent(
            this.identifier + "#did-root-key",
            this.identifier,
            this.privateKey!.publicKey,
            this.publicKeyFormat
        );
        await this.submitTransaction(DidMethodOperation.CREATE, event, this.privateKey!);

        return this;
    }

    public async changeOwner(args: { controller: string; newPrivateKey: PrivateKey }) {
        if (!this.identifier) {
            throw new DidError("DID is not registered");
        }

        this.validateClientConfig();

        if (!args.newPrivateKey) {
            throw new DidError("newPrivateKey is missing");
        }

        await this.resolve();

        if (!this.document!.hasOwner()) {
            throw new DidError("DID is not registered or was recently deleted. DID has to be registered first.");
        }

        /**
         * Change owner of the topic
         */
        const transaction = await new TopicUpdateTransaction()
            .setTopicId(this.topicId!)
            .setAdminKey(args.newPrivateKey.publicKey)
            .setSubmitKey(args.newPrivateKey.publicKey)
            .freezeWith(this.client!);

        const signTx = await (await transaction.sign(this.privateKey!)).sign(args.newPrivateKey);
        const txResponse = await signTx.execute(this.client!);
        await txResponse.getReceipt(this.client!);

        this.privateKey = args.newPrivateKey;

        /**
         * Send ownership change message to the topic
         */
        await this.submitTransaction(
            DidMethodOperation.UPDATE,
            new HcsDidUpdateDidOwnerEvent(
                this.getIdentifier() + "#did-root-key",
                args.controller,
                args.newPrivateKey.publicKey,
                this.publicKeyFormat
            ),
            this.privateKey
        );
        return this;
    }

    public async delete() {
        if (!this.identifier) {
            throw new DidError("DID is not registered");
        }

        this.validateClientConfig();

        await this.submitTransaction(DidMethodOperation.DELETE, new HcsDidDeleteEvent(), this.privateKey!);
        return this;
    }

    public async resolve(): Promise<DidDocument> {
        if (!this.identifier) {
            throw new DidError("DID is not registered");
        }

        if (!this.client) {
            throw new DidError("Client configuration is missing");
        }

        return new Promise((resolve, reject) => {
            // Instantiate the resolver with the topic ID and Mirror Node base URL
            const resolver = new HcsDidEventMessageResolver(this.topicId!, this.mirrorNodeUrl!);

            resolver
                .setTimeout(HcsDid.READ_TOPIC_MESSAGES_TIMEOUT)
                .whenFinished(async (messages) => {
                    try {
                        // Extract and process messages
                        this.messages = messages
                            .map((msg) => msg.open())
                            .filter((msg): msg is HcsDidMessage => msg !== null);

                        this.document = new DidDocument(this.identifier!, this.publicKeyFormat);
                        await this.document.processMessages(this.messages);
                        resolve(this.document);
                    } catch (err) {
                        reject(err);
                    }
                })
                .onError((err) => {
                    reject(err);
                })
                .execute(); // No client required for execution
        });
    }

    /**
     *  Meta-information about DID
     */

    /**
     * Add a Service meta-information to DID
     * @param args
     * @returns this
     */
    public async addService(args: { id: string; type: ServiceTypes; serviceEndpoint: string }) {
        this.validateClientConfig();

        const event = new HcsDidCreateServiceEvent(args.id, args.type, args.serviceEndpoint);
        await this.submitTransaction(DidMethodOperation.CREATE, event, this.privateKey!);

        return this;
    }

    /**
     * Update a Service meta-information to DID
     * @param args
     * @returns this
     */
    public async updateService(args: { id: string; type: ServiceTypes; serviceEndpoint: string }) {
        this.validateClientConfig();

        const event = new HcsDidUpdateServiceEvent(args.id, args.type, args.serviceEndpoint);
        await this.submitTransaction(DidMethodOperation.UPDATE, event, this.privateKey!);

        return this;
    }

    /**
     * Revoke a Service meta-information to DID
     * @param args
     * @returns this
     */
    public async revokeService(args: { id: string }) {
        this.validateClientConfig();

        const event = new HcsDidRevokeServiceEvent(args.id);
        await this.submitTransaction(DidMethodOperation.REVOKE, event, this.privateKey!);

        return this;
    }

    /**
     * Add a Verification Method meta-information to DID
     * @param args
     * @returns this
     */
    public async addVerificationMethod(args: {
        id: string;
        type: VerificationMethodSupportedKeyType;
        controller: string;
        publicKey: PublicKey;
    }) {
        this.validateClientConfig();

        const event = new HcsDidCreateVerificationMethodEvent(args.id, args.controller, args.publicKey, args.type);
        await this.submitTransaction(DidMethodOperation.CREATE, event, this.privateKey!);

        return this;
    }

    /**
     * Update a Verification Method meta-information to DID
     * @param args
     * @returns this
     */
    public async updateVerificationMethod(args: {
        id: string;
        type: VerificationMethodSupportedKeyType;
        controller: string;
        publicKey: PublicKey;
    }) {
        this.validateClientConfig();

        const event = new HcsDidUpdateVerificationMethodEvent(args.id, args.controller, args.publicKey, args.type);
        await this.submitTransaction(DidMethodOperation.UPDATE, event, this.privateKey!);

        return this;
    }

    /**
     * Revoke a Verification Method meta-information to DID
     * @param args
     * @returns this
     */
    public async revokeVerificationMethod(args: { id: string }) {
        this.validateClientConfig();

        const event = new HcsDidRevokeVerificationMethodEvent(args.id);
        await this.submitTransaction(DidMethodOperation.REVOKE, event, this.privateKey!);

        return this;
    }

    /**
     * Add a Verification Relationship to DID
     * @param args
     * @returns this
     */
    public async addVerificationRelationship(args: {
        id: string;
        relationshipType: VerificationRelationshipType;
        type: VerificationRelationshipSupportedKeyType;
        controller: string;
        publicKey: PublicKey;
    }) {
        this.validateClientConfig();

        const event = new HcsDidCreateVerificationRelationshipEvent(
            args.id,
            args.relationshipType,
            args.controller,
            args.publicKey,
            args.type
        );
        await this.submitTransaction(DidMethodOperation.CREATE, event, this.privateKey!);

        return this;
    }

    /**
     * Update a Verification Relationship to DID
     * @param args
     * @returns this
     */
    public async updateVerificationRelationship(args: {
        id: string;
        relationshipType: VerificationRelationshipType;
        type: VerificationRelationshipSupportedKeyType;
        controller: string;
        publicKey: PublicKey;
    }) {
        this.validateClientConfig();

        const event = new HcsDidUpdateVerificationRelationshipEvent(
            args.id,
            args.relationshipType,
            args.controller,
            args.publicKey,
            args.type
        );
        await this.submitTransaction(DidMethodOperation.UPDATE, event, this.privateKey!);

        return this;
    }

    /**
     * Revoke a Verification Relationship to DID
     * @param args
     * @returns this
     */
    public async revokeVerificationRelationship(args: { id: string; relationshipType: VerificationRelationshipType }) {
        this.validateClientConfig();

        const event = new HcsDidRevokeVerificationRelationshipEvent(args.id, args.relationshipType);
        await this.submitTransaction(DidMethodOperation.REVOKE, event, this.privateKey!);

        return this;
    }

    /**
     * Attribute getters
     */

    public getIdentifier() {
        return this.identifier;
    }

    public getClient() {
        return this.client;
    }

    public getPrivateKey() {
        return this.privateKey;
    }

    public getKeyType() {
        return this.keyType;
    }

    public getTopicId() {
        return this.topicId;
    }

    public getNetwork() {
        return this.network;
    }

    public getMethod() {
        return HcsDid.DID_METHOD;
    }

    public getMessages() {
        return this.messages;
    }

    /**
     * Static methods
     */
    public static publicKeyToIdString(publicKey: PublicKey, keyType: string): string {
        const publicKeyBytes = publicKey.toBytesRaw();

        if (keyType.toLowerCase() === "ed25519") {
            return getPublicKeyBase58ForEd25519(publicKeyBytes);
        } else if (keyType.toLowerCase() === "secp256k1") {
            if (!isValidCompressedOrUncompressedSecp256k1Key(publicKeyBytes)) {
                throw new Error("Invalid Secp256k1 public key format.");
            }
            return getPublicKeyBase58ForSecp256k1(publicKeyBytes);
        } else {
            throw new Error("Unsupported key type. Expected 'Ed25519' or 'Secp256k1'.");
        }
    }

    public static stringToPublicKey(idString: string): PublicKey {
        if (!idString.startsWith("z")) {
            throw new Error("Invalid multibase encoding. Expected prefix 'z'.");
        }

        const decodedBytes = base58btc.decode(idString.slice(1));

        if (decodedBytes[0] === MULTICODECS["ed25519-pub"][0]) {
            const publicKeyBytes = removeMulticodecPrefix("ed25519-pub", decodedBytes);
            return PublicKey.fromBytesED25519(publicKeyBytes);
        } else if (decodedBytes[0] === MULTICODECS["secp256k1-pub"][0]) {
            const publicKeyBytes = removeMulticodecPrefix("secp256k1-pub", decodedBytes);
            return PublicKey.fromBytesECDSA(publicKeyBytes);
        } else {
            throw new Error("Unsupported multicodec prefix. Cannot determine key type.");
        }
    }

    public static parsePublicKeyFromIdentifier(identifier: string): PublicKey {
        const [_networkName, _topicId, didIdString] = HcsDid.parseIdentifier(identifier);
        return HcsDid.stringToPublicKey(didIdString);
    }

    /**
     * Private
     */

    private buildIdentifier(publicKey: PublicKey): string {
        const methodNetwork = [this.getMethod().toString(), this.network].join(DidSyntax.DID_METHOD_SEPARATOR);

        let ret: string;
        ret =
            DidSyntax.DID_PREFIX +
            DidSyntax.DID_METHOD_SEPARATOR +
            methodNetwork +
            DidSyntax.DID_METHOD_SEPARATOR +
            HcsDid.publicKeyToIdString(publicKey, this.keyType) +
            DidSyntax.DID_TOPIC_SEPARATOR +
            this.topicId!.toString();

        return ret;
    }

    public static parseIdentifier(identifier: string): [string, TopicId, string] {
        const [didPart, topicIdPart] = identifier.split(DidSyntax.DID_TOPIC_SEPARATOR);

        if (!topicIdPart) {
            throw new DidError("DID string is invalid: topic ID is missing", DidErrorCode.INVALID_DID_STRING);
        }

        const topicId = TopicId.fromString(topicIdPart);

        const didParts = didPart.split(DidSyntax.DID_METHOD_SEPARATOR);

        if (didParts.shift() !== DidSyntax.DID_PREFIX) {
            throw new DidError("DID string is invalid: invalid prefix.", DidErrorCode.INVALID_DID_STRING);
        }

        const methodName = didParts.shift();
        if (DidSyntax.Method.HEDERA_HCS !== methodName) {
            throw new DidError(
                "DID string is invalid: invalid method name: " + methodName,
                DidErrorCode.INVALID_DID_STRING
            );
        }

        try {
            const networkName = didParts.shift();

            if (
                networkName != DidSyntax.HEDERA_NETWORK_MAINNET &&
                networkName != DidSyntax.HEDERA_NETWORK_TESTNET &&
                networkName != DidSyntax.HEDERA_NETWORK_PREVIEWNET
            ) {
                throw new DidError("DID string is invalid. Invalid Hedera network.", DidErrorCode.INVALID_NETWORK);
            }

            const didIdString = didParts.shift() || "";

            if (didIdString.length < 44 || didParts.shift()) {
                throw new DidError(
                    "DID string is invalid. ID holds incorrect format.",
                    DidErrorCode.INVALID_DID_STRING
                );
            }

            return [networkName, topicId, didIdString];
        } catch (e) {
            if (e instanceof DidError) {
                throw e;
            }

            throw new DidError("DID string is invalid. " + (e as Error).message, DidErrorCode.INVALID_DID_STRING);
        }
    }

    private validateClientConfig() {
        if (!this.privateKey) {
            throw new DidError("privateKey is missing");
        }

        if (!this.client) {
            throw new DidError("Client configuration is missing");
        }
    }

    /**
     * Submit Message Transaction to Hashgraph
     * @param didMethodOperation
     * @param event
     * @param privateKey
     * @returns this
     */
    private async submitTransaction(
        didMethodOperation: DidMethodOperation,
        event: HcsDidEvent,
        privateKey: PrivateKey
    ): Promise<TransactionId> {
        const message = new HcsDidMessage(didMethodOperation, this.getIdentifier()!, event);
        const envelope = new MessageEnvelope(message);
        let transaction = new HcsDidTransaction(envelope, this.getTopicId()!);

        transaction.signMessage((msg) => privateKey.sign(msg));
        const signedTransaction = transaction.buildAndSignTransaction((tx) => {
            return tx.setMaxTransactionFee(HcsDid.TRANSACTION_FEE).freezeWith(this.client!).sign(privateKey);
        });

        return await signedTransaction.execute(this.client!);
    }
}
