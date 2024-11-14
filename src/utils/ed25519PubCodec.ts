/**
 * Custom Ed25519 Public Key Codec
 * Encodes and decodes data with a predefined multicodec prefix.
 */
export class Ed25519PubCodec {
    // Codec metadata
    name: string = "ed25519-pub";
    code: number = 0xed;

    /**
     * Encodes data by prefixing it with the codec code.
     * @param {Uint8Array} data - The raw public key data.
     * @returns {Uint8Array} - Encoded data with codec prefix.
     */
    encode(data: Uint8Array): Uint8Array {
        const prefix = this.varintEncode(this.code);
        return this.concat([prefix, data], prefix.length + data.length);
    }

    /**
     * Decodes data by removing the codec prefix.
     * @param {Uint8Array} bytes - Encoded data with codec prefix.
     * @returns {Uint8Array} - Raw public key data.
     */
    decode(bytes: Uint8Array): Uint8Array {
        return this.rmPrefix(bytes);
    }

    /**
     * Concatenates multiple Uint8Arrays into a single Uint8Array.
     * @param {Uint8Array[]} arrays - Arrays to concatenate.
     * @param {number} length - Total length of the resulting array.
     * @returns {Uint8Array} - Concatenated array.
     */
    private concat(arrays: Uint8Array[], length: number): Uint8Array {
        const output = new Uint8Array(length);
        let offset = 0;
        for (const arr of arrays) {
            output.set(arr, offset);
            offset += arr.length;
        }
        return output;
    }

    /**
     * Encodes an integer using variable-length encoding.
     * @param {number} num - The integer to encode.
     * @returns {Uint8Array} - Varint encoded number.
     */
    private varintEncode(num: number): Uint8Array {
        const result = [];
        while (num >= 0x80) {
            result.push((num & 0x7f) | 0x80);
            num >>>= 7;
        }
        result.push(num);
        return Uint8Array.from(result);
    }

    /**
     * Removes the codec prefix from the encoded data.
     * @param {Uint8Array} data - Encoded data with prefix.
     * @returns {Uint8Array} - Data without prefix.
     */
    private rmPrefix(data: Uint8Array): Uint8Array {
        let bytesUsed = 0;
        for (let i = 0; i < data.length; i++) {
            bytesUsed++;
            if ((data[i] & 0x80) === 0) break;
        }
        return data.slice(bytesUsed);
    }
}
