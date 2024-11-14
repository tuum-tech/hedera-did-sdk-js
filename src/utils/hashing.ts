import * as crypto from "crypto";
import { Base64 } from "js-base64";
import { MultibaseDecoder, MultibaseEncoder } from "multiformats/bases/interface";
import { bases } from "multiformats/basics";

export class Hashing {
    public static readonly sha256 = {
        digest: function (data: Uint8Array | string): Uint8Array {
            const sha256 = crypto
                .createHash("sha256") // may need to change in the future.
                .update(data)
                .digest();
            return sha256;
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
            return bases.base58btc.decode(encodedString); // using multiformats for base58 decoding
        },
        encode: function (decodedBytes: Uint8Array): string {
            return bases.base58btc.encode(decodedBytes); // using multiformats for base58 encoding
        },
    };

    /**
     * @returns Multibase [MULTIBASE] base58-btc encoded value that is a concatenation of the
     * MULTIBASE(base58-btc, raw-public-key-bytes)
     * https://github.com/multiformats/multibase
     * https://www.w3.org/TR/did-core/#dfn-publickeymultibase
     */
    public static readonly multibase = {
        encode: function (data: Uint8Array, base: MultibaseEncoder<string> = bases.base58btc): string {
            return base.encode(data);
        },
        decode: function (data: string, base: MultibaseDecoder<string> = bases.base58btc): Uint8Array {
            return base.decode(data);
        },
    };
}
