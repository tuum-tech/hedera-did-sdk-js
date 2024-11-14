import { HcsDidEvent } from "../hcs-did-event";
import { HcsDidEventTargetName } from "../hcs-did-event-target-name";

export class HcsDidDeleteEvent extends HcsDidEvent {
    public readonly targetName = HcsDidEventTargetName.Document;

    constructor() {
        super();
    }

    getId(): string {
        return "";
    }

    public toJsonTree() {
        return null;
    }

    public toJSON() {
        return JSON.stringify(this.toJsonTree());
    }

    public getBase64() {
        return "";
    }

    static fromJsonTree(tree: any): HcsDidDeleteEvent {
        return new HcsDidDeleteEvent();
    }
}
