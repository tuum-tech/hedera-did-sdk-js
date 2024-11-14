// @ts-check

import { BlockCodec, ByteView } from "multiformats/codecs/interface";

/**
 * Ed25519PubCodec MULTICODEC(public-key-type, raw-public-key-bytes)
 * https://github.com/multiformats/js-multiformats#multicodec-encoders--decoders--codecs
 * Implementation of BlockCodec interface which implements both BlockEncoder and BlockDecoder.
 * @template T
 * @typedef {import('./interface').ByteView<T>} ByteView
 */

export class Ed25519PubCodec implements BlockCodec<number, Uint8Array> {
    // values retrieved from https://raw.githubusercontent.com/multiformats/multicodec/master/table.csv
    name: string = "ed25519-pub";
    code: number = 0xed;

    encode(data: Uint8Array): ByteView<Uint8Array> {
        const prefix = this.varintEncode(this.code);
        return this.concat([prefix, data], prefix.length + data.length);
    }

    decode(bytes: ByteView<Uint8Array>): Uint8Array {
        return this.rmPrefix(bytes);
    }

    /**
     * Returns a new Uint8Array created by concatenating the passed ArrayLikes
     *
     * @param {Array<ArrayLike<number>>} arrays
     * @param {number} [length]
     */
    private concat(arrays: Array<ArrayLike<number>>, length: number) {
        if (!length) {
            length = arrays.reduce((acc, curr) => acc + curr.length, 0);
        }

        const output = new Uint8Array(length);
        let offset = 0;

        for (const arr of arrays) {
            output.set(arr, offset);
            offset += arr.length;
        }

        return output;
    }

    /**
     * Encodes a number as varint.
     * @param {number} num
     * @returns {Uint8Array}
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
     * Decodes a varint from a Uint8Array and returns the number.
     * Also adjusts the view to skip the varint bytes.
     * @param {Uint8Array} data
     * @returns {Uint8Array}
     */
    private rmPrefix(data: Uint8Array): Uint8Array {
        let num = 0;
        let shift = 0;
        let bytesUsed = 0;

        for (let i = 0; i < data.length; i++) {
            const byte = data[i];
            num |= (byte & 0x7f) << shift;
            shift += 7;
            bytesUsed++;
            if ((byte & 0x80) === 0) break;
        }

        return data.slice(bytesUsed);
    }
}
