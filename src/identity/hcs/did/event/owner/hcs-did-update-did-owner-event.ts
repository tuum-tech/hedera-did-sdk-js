import { parsePublicKey } from "../../../../../utils/crypto-utils";
import { HcsDidCreateDidOwnerEvent } from "./hcs-did-create-did-owner-event";

export class HcsDidUpdateDidOwnerEvent extends HcsDidCreateDidOwnerEvent {
    static fromJsonTree(tree: any): HcsDidUpdateDidOwnerEvent {
        const { publicKey, publicKeyFormat } = parsePublicKey(tree);
        return new HcsDidUpdateDidOwnerEvent(tree?.id, tree?.controller, publicKey, publicKeyFormat);
    }
}
