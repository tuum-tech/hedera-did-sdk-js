import { Hashing } from "../../../../utils/hashing";
import { DidMethodOperation } from "../../../did-method-operation";
import { HcsDidCreateDidDocumentEvent } from "./document/hcs-did-create-did-document-event";
import { HcsDidDeleteEvent } from "./document/hcs-did-delete-event";
import { HcsDidEvent } from "./hcs-did-event";
import { HcsDidEventTargetName } from "./hcs-did-event-target-name";
import { HcsDidCreateDidOwnerEvent } from "./owner/hcs-did-create-did-owner-event";
import { HcsDidUpdateDidOwnerEvent } from "./owner/hcs-did-update-did-owner-event";
import { HcsDidCreateServiceEvent } from "./service/hcs-did-create-service-event";
import { HcsDidRevokeServiceEvent } from "./service/hcs-did-revoke-service-event";
import { HcsDidUpdateServiceEvent } from "./service/hcs-did-update-service-event";
import { HcsDidCreateVerificationMethodEvent } from "./verification-method/hcs-did-create-verification-method-event";
import { HcsDidRevokeVerificationMethodEvent } from "./verification-method/hcs-did-revoke-verification-method-event";
import { HcsDidUpdateVerificationMethodEvent } from "./verification-method/hcs-did-update-verification-method-event";
import { HcsDidCreateVerificationRelationshipEvent } from "./verification-relationship/hcs-did-create-verification-relationship-event";
import { HcsDidRevokeVerificationRelationshipEvent } from "./verification-relationship/hcs-did-revoke-verification-relationship-event";
import { HcsDidUpdateVerificationRelationshipEvent } from "./verification-relationship/hcs-did-update-verification-relationship-event";

const EVENT_NAME_TO_CLASS: Record<string, Record<string, any>> = {
    create: {
        DIDOwner: HcsDidCreateDidOwnerEvent,
        DIDDocument: HcsDidCreateDidDocumentEvent,
        Service: HcsDidCreateServiceEvent,
        VerificationMethod: HcsDidCreateVerificationMethodEvent,
        VerificationRelationship: HcsDidCreateVerificationRelationshipEvent,
    },
    update: {
        DIDOwner: HcsDidUpdateDidOwnerEvent,
        Service: HcsDidUpdateServiceEvent,
        VerificationMethod: HcsDidUpdateVerificationMethodEvent,
        VerificationRelationship: HcsDidUpdateVerificationRelationshipEvent,
    },
    revoke: {
        Service: HcsDidRevokeServiceEvent,
        VerificationMethod: HcsDidRevokeVerificationMethodEvent,
        VerificationRelationship: HcsDidRevokeVerificationRelationshipEvent,
    },
};

const OPERATION_MAP: Record<DidMethodOperation, string> = {
    [DidMethodOperation.CREATE_DID_DOCUMENT]: "create-did-document",
    [DidMethodOperation.CREATE]: "create",
    [DidMethodOperation.UPDATE]: "update",
    [DidMethodOperation.REVOKE]: "revoke",
    [DidMethodOperation.DELETE]: "delete",
};

export class HcsDidEventParser {
    /**
     * Parses an event from a Base64-encoded string.
     *
     * @param operation The DID operation type.
     * @param eventBase64 The Base64-encoded event.
     * @return An instance of HcsDidEvent.
     */
    static fromBase64(operation: DidMethodOperation, eventBase64: any): HcsDidEvent {
        if (operation === DidMethodOperation.DELETE) {
            return HcsDidDeleteEvent.fromJsonTree(null);
        }

        try {
            const tree = JSON.parse(Hashing.base64.decode(eventBase64));
            const eventsByOperation = EVENT_NAME_TO_CLASS[OPERATION_MAP[operation]];
            const eventTargetName = Object.keys(eventsByOperation).find((etn) => !!tree[etn]);

            if (eventTargetName && eventsByOperation[eventTargetName]) {
                return eventsByOperation[eventTargetName].fromJsonTree(tree[eventTargetName]);
            }
            return new HcsDidEmptyEvent();
        } catch {
            return new HcsDidEmptyEvent();
        }
    }

    /**
     * Parses an event directly from a JSON object.
     *
     * @param operation The DID operation type.
     * @param eventJson The JSON object representing the event.
     * @return An instance of HcsDidEvent.
     */
    static fromJson(operation: DidMethodOperation, eventJson: any): HcsDidEvent {
        if (operation === DidMethodOperation.DELETE) {
            return HcsDidDeleteEvent.fromJsonTree(null);
        }

        try {
            const eventsByOperation = EVENT_NAME_TO_CLASS[OPERATION_MAP[operation]];
            const eventTargetName = Object.keys(eventsByOperation).find((etn) => !!eventJson[etn]);

            if (eventTargetName && eventsByOperation[eventTargetName]) {
                return eventsByOperation[eventTargetName].fromJsonTree(eventJson[eventTargetName]);
            }
            return new HcsDidEmptyEvent();
        } catch (err) {
            console.error("Error in fromJson: ", err); // Debug
            return new HcsDidEmptyEvent();
        }
    }
}

export class HcsDidEmptyEvent extends HcsDidEvent {
    // Define the target name as an empty or default value
    public readonly targetName = HcsDidEventTargetName.NONE;

    constructor() {
        super();
    }

    // Implement getId with a placeholder ID
    getId(): string {
        return "empty-event";
    }

    // Return a minimal or empty JSON tree
    toJsonTree(): any {
        return {};
    }

    // Return a minimal or empty JSON representation
    toJSON(): string {
        return JSON.stringify({});
    }
}
