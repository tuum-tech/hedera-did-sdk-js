import { HcsDidCreateDidDocumentEvent } from "../identity/hcs/did/event/document/hcs-did-create-did-document-event";

const IPFS_IO_HTTP_PROXY = "https://ipfs.io/ipfs/";

export class IpfsDidDocumentDownloader {
    constructor(private readonly ipfsHttpProxy: string = IPFS_IO_HTTP_PROXY) {}

    async downloadDocument(docEvent: HcsDidCreateDidDocumentEvent) {
        const url = docEvent.getUrl() ?? `${this.ipfsHttpProxy}/${docEvent.getCid}`;
        console.log("ipfs url: ", url);

        const result = await fetch(url); // Using the native fetch API
        console.log("result: ", JSON.stringify(result, null, 2));
        if (!result.ok) {
            throw new Error(`DID document could not be fetched from URL: ${url}`);
        }

        try {
            return await result.json();
        } catch (err) {
            throw new Error(`DID document from URL could not be parsed as JSON: ${url}`);
        }
    }
}
