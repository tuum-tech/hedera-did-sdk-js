import { PublicKey } from "@hashgraph/sdk";
import { createJWK, isJWK } from "@veramo/utils";
import { ec } from "elliptic";
import { base58btc } from "multiformats/bases/base58";
import { DidError } from "../identity/did-error";
import { DidSyntax } from "../identity/did-syntax";
import { ECDSA_SECP256K1_KEY_TYPE, ED25519_KEY_TYPE, JSON_WEB_KEY_TYPE } from "../identity/hcs/did/hcs-did-key-type";

export type CodecName = "secp256k1-priv" | "secp256k1-pub" | "ed25519-priv" | "ed25519-pub";

export const MULTICODECS: Record<CodecName, Uint8Array> = {
    "secp256k1-priv": new Uint8Array([129, 38]),
    "secp256k1-pub": new Uint8Array([231, 1]),
    "ed25519-priv": new Uint8Array([128, 38]),
    "ed25519-pub": new Uint8Array([237, 1]),
};

export const addMulticodecPrefix = (multicodec: CodecName, data: Uint8Array): Uint8Array => {
    let prefix;

    if (MULTICODECS[multicodec]) {
        prefix = Buffer.from(MULTICODECS[multicodec]);
    } else {
        throw new Error("multicodec not recognized");
    }

    return Buffer.concat([prefix, data], prefix.length + data.length);
};

export const removeMulticodecPrefix = (multicodec: CodecName, data: Uint8Array): Uint8Array => {
    const prefix = MULTICODECS[multicodec];
    if (!prefix) {
        throw new Error("multicodec not recognized");
    }

    const prefixLength = prefix.length;
    if (!data.slice(0, prefixLength).every((byte, index) => byte === prefix[index])) {
        throw new Error("Invalid multicodec prefix");
    }

    return data.slice(prefixLength);
};

export const getPublicKeyBase58ForEd25519 = (publicKey: Uint8Array): string => {
    if (publicKey.length !== 32) {
        throw new Error("Invalid Ed25519 public key length. Expected 32 bytes.");
    }
    const prefixedKey = addMulticodecPrefix("ed25519-pub", publicKey);
    return base58btc.encode(prefixedKey);
};

export const getPublicKeyBase58ForSecp256k1 = (publicKey: Uint8Array): string => {
    // Determine if the key is compressed or uncompressed
    if (publicKey[0] === 0x04) {
        // Uncompressed key (65 bytes, starts with 0x04)
        const compressedKey = getCompressedPublicKey(publicKey);
        const compressedKeyBytes = Uint8Array.from(Buffer.from(compressedKey, "hex"));
        const prefixedKey = addMulticodecPrefix("secp256k1-pub", compressedKeyBytes);
        return base58btc.encode(prefixedKey);
    } else if (publicKey[0] === 0x02 || publicKey[0] === 0x03) {
        // Compressed key (33 bytes, starts with 0x02 or 0x03)
        const prefixedKey = addMulticodecPrefix("secp256k1-pub", publicKey);
        return base58btc.encode(prefixedKey);
    } else {
        throw new Error(`Invalid Secp256k1 public key. Must be compressed or uncompressed. ${publicKey}`);
    }
};

export const isValidCompressedOrUncompressedSecp256k1Key = (key: Uint8Array): boolean => {
    return (
        (key.length === 33 && (key[0] === 0x02 || key[0] === 0x03)) || // Compressed
        (key.length === 65 && key[0] === 0x04) // Uncompressed
    );
};

export const getCompressedPublicKey = (uncompressedKey: Uint8Array): string => {
    const x = uncompressedKey.slice(1, 33);
    const y = uncompressedKey.slice(33);
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;
    return Buffer.from([prefix, ...x]).toString("hex");
};

export const decompressPublicKey = (compressedKey: Uint8Array): Uint8Array => {
    const secp256k1 = new ec("secp256k1");
    const key = secp256k1.keyFromPublic(compressedKey, "hex");
    const pubPoint = key.getPublic();
    return new Uint8Array(pubPoint.encode("array", false)); // false for uncompressed
};

export function detectKeyTypeFromPublicKey(publicKey: PublicKey): string {
    const publicKeyBytes = publicKey.toBytesRaw();

    if (publicKeyBytes.length === 32) {
        // Ed25519 public keys are always 32 bytes
        return "Ed25519";
    } else if (publicKeyBytes.length === 33 && (publicKeyBytes[0] === 0x02 || publicKeyBytes[0] === 0x03)) {
        // 33-byte compressed Secp256k1 keys start with 0x02 or 0x03
        return "Secp256k1";
    } else if (publicKeyBytes.length === 65 && publicKeyBytes[0] === 0x04) {
        // 65-byte uncompressed Secp256k1 keys start with 0x04
        return "Secp256k1";
    } else {
        throw new Error(
            `Unable to detect curve from public key. Unsupported key length or format: ${publicKeyBytes.length}`
        );
    }
}

export function detectKeyTypeFromPublicKeyBytes(publicKeyBytes: Uint8Array): string {
    if (publicKeyBytes.length === 32) {
        // Ed25519 public keys are always 32 bytes
        return "Ed25519";
    } else if (publicKeyBytes.length === 33 && (publicKeyBytes[0] === 0x02 || publicKeyBytes[0] === 0x03)) {
        // 33-byte compressed Secp256k1 keys start with 0x02 or 0x03
        return "Secp256k1";
    } else if (publicKeyBytes.length === 65 && publicKeyBytes[0] === 0x04) {
        // 65-byte uncompressed Secp256k1 keys start with 0x04
        return "Secp256k1";
    } else {
        throw new Error(
            `Unable to detect curve from public key. Unsupported key length or format: ${publicKeyBytes.length}`
        );
    }
}

export function detectKeyTypeFromIdentifier(identifier: string): string {
    // Ensure the identifier follows the expected format
    if (!identifier.startsWith("did:hedera:")) {
        throw new DidError("Invalid identifier format. Expected it to start with 'did:hedera:'.");
    }

    // Split the identifier into its components
    const parts = identifier.split(DidSyntax.DID_METHOD_SEPARATOR);
    if (parts.length < 4) {
        throw new DidError("Invalid identifier format. Missing multibase key or topic ID.");
    }

    // Extract the multibase-encoded key part of the identifier
    const keyAndTopic = parts[3]; // Fourth part contains the key and topic ID
    const multibaseKey = keyAndTopic.split(DidSyntax.DID_TOPIC_SEPARATOR)[0]; // Extract only the key

    if (!multibaseKey.startsWith("z")) {
        throw new DidError(`Invalid multibase encoding. Expected prefix 'z', got '${multibaseKey[0]}'.`);
    }

    // Decode the multibase key (keep the 'z' prefix intact for decoding)
    const decodedBytes = base58btc.decode(multibaseKey); // No slicing needed here

    // Check the prefix to determine the key type
    if (decodedBytes[0] === MULTICODECS["ed25519-pub"][0] && decodedBytes[1] === MULTICODECS["ed25519-pub"][1]) {
        // Matches Ed25519 multicodec prefix
        return "Ed25519";
    } else if (
        decodedBytes[0] === MULTICODECS["secp256k1-pub"][0] &&
        decodedBytes[1] === MULTICODECS["secp256k1-pub"][1]
    ) {
        // Matches Secp256k1 multicodec prefix
        return "Secp256k1";
    } else {
        throw new DidError("Unable to detect curve from identifier. Unsupported multicodec prefix.");
    }
}

/**
 * Generate the definition based on the key type.
 */
export function generateDefinition(
    id: string,
    keyType: string,
    controller: string,
    publicKeyMultibaseOrBytes: string | Uint8Array,
    publicKeyFormat: string
) {
    if (publicKeyFormat === JSON_WEB_KEY_TYPE) {
        if (!(publicKeyMultibaseOrBytes instanceof Uint8Array)) {
            throw new DidError("Expected Uint8Array for JWK generation");
        }
        return {
            id,
            type: publicKeyFormat,
            controller,
            publicKeyJwk: createJWK(keyType as any, publicKeyMultibaseOrBytes as Uint8Array, "sig"),
        };
    } else {
        if (typeof publicKeyMultibaseOrBytes !== "string") {
            throw new DidError("Expected string for multibase public key");
        }
        return {
            id,
            type: publicKeyFormat,
            controller,
            publicKeyMultibase: publicKeyMultibaseOrBytes as string,
        };
    }
}

/**
 * Get the public key multibase representation.
 */
export function getPublicKeyMultibaseString(keyType: string, publicKeyBytes: Uint8Array): string {
    if (keyType === ECDSA_SECP256K1_KEY_TYPE) {
        return getPublicKeyBase58ForSecp256k1(publicKeyBytes);
    } else if (keyType === ED25519_KEY_TYPE) {
        return getPublicKeyBase58ForEd25519(publicKeyBytes);
    } else {
        throw new DidError("Unsupported key type for Base58 encoding");
    }
}

/**
 * Parse the public key from the JSON tree.
 */
export function parsePublicKey(tree: any): { publicKey: PublicKey; publicKeyFormat: string } {
    const publicKeyFormat = tree?.type || ED25519_KEY_TYPE; // Default to Ed25519VerificationKey2020 if type is missing
    let publicKeyBytes: Uint8Array;

    if (tree?.publicKeyMultibase) {
        const decodedBytes = base58btc.decode(tree.publicKeyMultibase);

        if (publicKeyFormat === ECDSA_SECP256K1_KEY_TYPE) {
            publicKeyBytes = removeMulticodecPrefix("secp256k1-pub", decodedBytes);
        } else if (publicKeyFormat === ED25519_KEY_TYPE) {
            publicKeyBytes = removeMulticodecPrefix("ed25519-pub", decodedBytes);
        } else {
            throw new DidError("Unsupported key type in JSON tree");
        }
    } else if (tree?.publicKeyJwk) {
        try {
            publicKeyBytes = getPublicKeyFromJWK(tree.publicKeyJwk); // Use utility to reconstruct the key
        } catch (err: any) {
            console.error("Error reconstructing public key from JWK: ", err);
            throw new DidError("Failed to reconstruct public key from JWK: " + err.message);
        }
    } else {
        throw new DidError("Missing publicKeyMultibase or publicKeyJwk in the JSON tree");
    }

    const keyType = detectKeyTypeFromPublicKeyBytes(publicKeyBytes);
    let publicKey;
    if (keyType === "Secp256k1") {
        publicKey = PublicKey.fromBytesECDSA(compressSecp256k1PublicKey(publicKeyBytes));
    } else if (keyType === "Ed25519") {
        publicKey = PublicKey.fromBytesED25519(publicKeyBytes);
    }

    return {
        publicKey: publicKey as PublicKey,
        publicKeyFormat,
    };
}

export function getPublicKeyFromJWK(jwk: JsonWebKey): Uint8Array {
    if (!isJWK(jwk)) {
        throw new Error("Invalid JWK");
    }

    switch (jwk.crv) {
        case "secp256k1": {
            if (jwk.kty !== "EC" || !jwk.x || !jwk.y) {
                throw new Error("Invalid secp256k1 JWK");
            }
            const x = base64urlToBytes(jwk.x);
            const y = base64urlToBytes(jwk.y);

            // Uncompressed key: [0x04, xBytes, yBytes]
            return Uint8Array.of(0x04, ...x, ...y);
        }
        case "P-256": {
            if (jwk.kty !== "EC" || !jwk.x || !jwk.y) {
                throw new Error("Invalid P-256 JWK");
            }
            const x = base64urlToBytes(jwk.x);
            const y = base64urlToBytes(jwk.y);

            // Uncompressed key: [0x04, xBytes, yBytes]
            return Uint8Array.of(0x04, ...x, ...y);
        }
        case "Ed25519":
        case "X25519": {
            if (jwk.kty !== "OKP" || !jwk.x) {
                throw new Error("Invalid Ed25519/X25519 JWK");
            }
            // Key is just the x-coordinate
            return base64urlToBytes(jwk.x);
        }
        default:
            throw new Error(`Unsupported curve: ${jwk.crv}`);
    }
}

/**
 * Helper: Converts Base64URL string to Uint8Array
 */
function base64urlToBytes(base64url: string): Uint8Array {
    const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function compressSecp256k1PublicKey(uncompressedKey: Uint8Array): Uint8Array {
    if (uncompressedKey.length !== 65 || uncompressedKey[0] !== 0x04) {
        throw new Error("Invalid uncompressed Secp256k1 public key");
    }

    const x = uncompressedKey.slice(1, 33); // First 32 bytes after 0x04
    const y = uncompressedKey.slice(33); // Last 32 bytes

    // Determine the prefix: 0x02 for even Y, 0x03 for odd Y
    const prefix = y[y.length - 1] % 2 === 0 ? 0x02 : 0x03;

    // Return compressed key: [prefix, X-coordinate]
    return Uint8Array.of(prefix, ...x);
}
