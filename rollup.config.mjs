import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";

export default {
    input: "src/index.ts", // entry file for the SDK
    output: {
        file: "dist/index.js", // output file
        format: "es", // ensures ES module format
    },
    context: "this", // sets the global `this` context
    external: [
        "uint8arrays", // Treat this as an external dependency
        "multiformats", // Treat this as an external dependency
    ],
    plugins: [
        resolve({
            browser: true, // ensures we get browser-compatible versions
            preferBuiltins: false, // avoid Node built-ins
            extensions: [".js", ".ts"], // Ensure TypeScript files are resolved
        }),
        commonjs(), // Transpile CommonJS modules to ESM
        json(), // Handle JSON imports, if any
        typescript({
            tsconfig: "./tsconfig.json",
            include: ["src/**/*.ts"],
        }), // Transpile TypeScript to JavaScript
    ],
};
