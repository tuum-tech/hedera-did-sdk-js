import { parsePublicKey } from "../../../../../utils/crypto-utils";
import { HcsDidCreateVerificationMethodEvent } from "./hcs-did-create-verification-method-event";

export class HcsDidUpdateVerificationMethodEvent extends HcsDidCreateVerificationMethodEvent {
    static fromJsonTree(tree: any): HcsDidCreateVerificationMethodEvent {
        const { publicKey, publicKeyFormat } = parsePublicKey(tree);
        return new HcsDidUpdateVerificationMethodEvent(tree?.id, tree?.controller, publicKey, publicKeyFormat);
    }
}
