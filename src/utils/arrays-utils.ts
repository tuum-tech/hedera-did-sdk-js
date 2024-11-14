export class ArraysUtils {
    public static equals(a: Uint8Array, b: Uint8Array): boolean {
        if (a === b) {
            return true;
        }
        if (!a || !b || a.length !== b.length) {
            return false;
        }
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    public static toString(array: number[] | Uint8Array): string {
        const uint8Array = Array.isArray(array) ? new Uint8Array(array) : array;
        return new TextDecoder("utf-8").decode(uint8Array);
    }

    public static fromString(text: string): Uint8Array {
        return new TextEncoder().encode(text);
    }
}
