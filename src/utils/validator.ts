import { DidError } from "../identity/did-error";

export class Validator {
    protected validationErrors: string[] = [];

    public addValidationError(errorMessage: string): void {
        if (!this.validationErrors) {
            this.validationErrors = [];
        }
        this.validationErrors.push(errorMessage);
    }

    public checkValidationErrors(prologue: string, validationFunction: (input: Validator) => void): void {
        this.validationErrors = [];

        validationFunction(this);

        // If there are no errors, exit early
        if (this.validationErrors.length === 0) {
            return;
        }

        const errors = this.validationErrors;
        this.validationErrors = []; // Clear errors after processing

        throw new DidError(prologue + ":\n" + errors.join("\n"));
    }

    public require(condition: boolean, errorMessage: string): void {
        if (!condition) {
            this.addValidationError(errorMessage);
        }
    }
}
