import { Timestamp, TopicId } from "@hashgraph/sdk";
import Long from "long";
import { DidError } from "../../..";
import { TimestampUtils } from "../../../utils/timestamp-utils";
import { DidMethodOperation } from "../../did-method-operation";
import { DidParser } from "../../did-parser";
import { HcsDidEvent } from "./event/hcs-did-event";
import { HcsDidEventParser } from "./event/hcs-did-event-parser";
import { HcsDid } from "./hcs-did";

export type Signer<T> = (message: T) => T;

/**
 * The DID document message submitted to appnet's DID Topic.
 */
export class HcsDidMessage {
    private static serialVersionUID = Long.fromInt(1);

    protected timestamp: Timestamp;
    protected operation: DidMethodOperation;
    protected did: string;
    protected event: HcsDidEvent;

    /**
     * Creates a new instance of {@link HcsDidMessage}.
     *
     * @param operation         The operation on DID document.
     * @param did               The DID string.
     * @param event             The DID Event.
     */
    constructor(operation: DidMethodOperation, did: string, event: HcsDidEvent) {
        this.timestamp = TimestampUtils.now();
        this.operation = operation;
        this.did = did;
        this.event = event;
    }

    public getTimestamp(): Timestamp {
        return this.timestamp;
    }

    public getOperation(): DidMethodOperation {
        return this.operation;
    }

    public getDid(): string {
        return this.did;
    }

    public getEvent(): HcsDidEvent {
        return this.event;
    }

    public getEventBase64() {
        return this.getEvent().getBase64();
    }

    /**
     * Validates this DID message by checking its completeness, signature and DID document.
     *
     * @param didTopicId The DID topic ID against which the message is validated.
     * @return True if the message is valid, false otherwise.
     */
    public isValid(): boolean;
    public isValid(didTopicId: TopicId): boolean;
    public isValid(...args: any[]): boolean {
        const didTopicId: TopicId = args[0] || null;

        if (this.did == null || this.event == null || this.operation == null) {
            return false;
        }

        try {
            const hcsDid: HcsDid = DidParser.parse(this.did);

            // Verify that the message was sent to the right topic, if the DID contains the topic
            if (
                !!didTopicId &&
                hcsDid.getTopicId()?.toString() &&
                didTopicId.toString() != hcsDid.getTopicId()?.toString()
            ) {
                return false;
            }
        } catch (e) {
            return false;
        }

        return true;
    }

    public toJsonTree(): any {
        const result: any = { timestamp: TimestampUtils.toJSON(this.timestamp) };
        result.operation = this.operation;
        result.did = this.did;

        // Handle the event serialization
        if (this.event) {
            if (typeof this.event.toJsonTree === "function") {
                // If the event has a `toJsonTree` method, use it
                result.event = this.event.toJsonTree();
            } else if (typeof this.event === "object") {
                // If the event is a plain object, include it as-is
                result.event = this.event;
            } else {
                // Fallback to Base64 serialization
                result.event = this.getEventBase64();
            }
        } else {
            result.event = null; // Handle null or undefined events
        }

        return result;
    }

    public static fromJsonTree(tree: any, result?: HcsDidMessage): HcsDidMessage {
        let event;

        if (typeof tree.event === "string") {
            // If it's a Base64-encoded string, decode it
            event = HcsDidEventParser.fromBase64(tree.operation, tree.event);
        } else if (typeof tree.event === "object") {
            // Use the JSON object directly
            event = HcsDidEventParser.fromJson(tree.operation, tree.event);
        } else {
            throw new DidError("Invalid event format in HcsDidMessage.fromJsonTree");
        }

        if (!result) {
            result = new HcsDidMessage(tree.operation, tree.did, event);
        } else {
            result.operation = tree.operation;
            result.did = tree.did;
            result.event = event;
        }
        result.timestamp = TimestampUtils.fromJson(tree.timestamp);
        return result;
    }

    public toJSON(): string {
        return JSON.stringify(this.toJsonTree());
    }

    public static fromJson(json: string): HcsDidMessage {
        return HcsDidMessage.fromJsonTree(JSON.parse(json));
    }
}
