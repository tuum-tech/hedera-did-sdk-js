import * as Base58 from "base58-js";
import { Base64 } from "js-base64";
import { sha256 } from "js-sha256";

export class Hashing {
    public static readonly sha256 = {
        digest: function (data: Uint8Array | string): Uint8Array {
            // js-sha256 expects strings or arrays and returns a Uint8Array by default
            const hashArray = sha256.arrayBuffer(data);
            return new Uint8Array(hashArray);
        },
    };

    public static readonly base64 = {
        decode: function (encodedString: string): string {
            return Base64.fromBase64(encodedString);
        },
        encode: function (decodedBytes: string): string {
            return Base64.toBase64(decodedBytes);
        },
    };

    public static readonly base58 = {
        decode: function (encodedString: string): Uint8Array {
            return Base58.base58_to_binary(encodedString);
        },
        encode: function (decodedBytes: Uint8Array): string {
            return Base58.binary_to_base58(decodedBytes);
        },
    };

    /**
     * @returns Multibase [MULTIBASE] base58-btc encoded value that is a concatenation of the
     * MULTIBASE(base58-btc, raw-public-key-bytes)
     * https://www.w3.org/TR/did-core/#dfn-publickeymultibase
     */
    public static readonly multibase = {
        /**
         * Encodes data using base58 encoding with a "z" prefix (multibase style).
         */
        encode: function (data: Uint8Array): string {
            return "z" + Hashing.base58.encode(data);
        },
        /**
         * Decodes a multibase (base58btc) encoded string, ensuring it starts with the "z" prefix.
         */
        decode: function (data: string): Uint8Array {
            if (!data.startsWith("z")) {
                throw new Error("Invalid multibase encoding. Expected prefix 'z'.");
            }
            return Hashing.base58.decode(data.slice(1));
        },
    };
}
