import { parsePublicKey } from "../../../../../utils/crypto-utils";
import { HcsDidCreateVerificationRelationshipEvent } from "./hcs-did-create-verification-relationship-event";

export class HcsDidUpdateVerificationRelationshipEvent extends HcsDidCreateVerificationRelationshipEvent {
    static fromJsonTree(tree: any): HcsDidUpdateVerificationRelationshipEvent {
        const { publicKey, publicKeyFormat } = parsePublicKey(tree);
        return new HcsDidUpdateVerificationRelationshipEvent(
            tree?.id,
            tree?.relationshipType,
            tree?.controller,
            publicKey,
            publicKeyFormat
        );
    }
}
