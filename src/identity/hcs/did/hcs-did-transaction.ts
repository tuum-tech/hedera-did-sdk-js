import { Client, TopicId, TopicMessageSubmitTransaction, Transaction, TransactionId } from "@hashgraph/sdk";
import dayjs from "dayjs";
import utc from "dayjs/plugin/utc";
import { ArraysUtils } from "../../../utils/arrays-utils";
import { Validator } from "../../../utils/validator";
import { DidError } from "../../did-error";
import { MessageEnvelope } from "../message-envelope";
import { HcsDidMessage, Signer } from "./hcs-did-message";
import { HcsDidTopicListener } from "./hcs-did-topic-listener";

dayjs.extend(utc);

/**
 * The DID document creation, update or deletion transaction.
 * Builds a correct {@link HcsDidMessage} and send it to HCS DID topic.
 */
export class HcsDidTransaction {
    private static SUBTRACT_TIME = 1; // seconds

    protected topicId: TopicId;
    protected message: MessageEnvelope<HcsDidMessage>;

    private buildTransactionFunction?: (input: TopicMessageSubmitTransaction) => Promise<Transaction>;
    private receiver?: (input: MessageEnvelope<HcsDidMessage>) => void;
    private errorHandler?: (input: Error) => void;
    private executed: boolean = false;
    private signer?: Signer<Uint8Array>;
    private listener?: HcsDidTopicListener;

    /**
     * Instantiates a new transaction object from a message that was already prepared.
     *
     * @param topicId The HCS DID topic ID where message will be submitted.
     * @param message The message envelope.
     */
    constructor(message: MessageEnvelope<HcsDidMessage>, topicId: TopicId) {
        if (message instanceof MessageEnvelope && topicId instanceof TopicId) {
            this.topicId = topicId;
            this.message = message;
            this.executed = false;
        } else {
            throw new DidError("Invalid arguments");
        }
    }

    /**
     * Provides a {@link MessageListener} instance specific to the submitted message type.
     *
     * @param topicIdToListen ID of the HCS topic.
     * @return The topic listener for this message on a mirror node.
     */
    protected provideTopicListener(topicIdToListen: TopicId, baseUrl: string): HcsDidTopicListener {
        return new HcsDidTopicListener(topicIdToListen, baseUrl);
    }

    /**
     * Handles the error.
     * If external error handler is defined, passes the error there, otherwise raises RuntimeException.
     *
     * @param err The error.
     * @throws RuntimeException Runtime exception with the given error in case external error handler is not defined.
     */
    protected handleError(err: Error): void {
        if (this.errorHandler) {
            this.errorHandler(err);
        } else {
            throw new DidError(err.message);
        }
    }

    /**
     * Defines a handler for errors when they happen during execution.
     *
     * @param handler The error handler.
     * @return This transaction instance.
     */
    public onError(handler: (input: Error) => void): HcsDidTransaction {
        this.errorHandler = handler;
        return this;
    }

    /**
     * Defines a function that signs the message.
     *
     * @param signer The signing function to set.
     * @return This transaction instance.
     */
    public signMessage(signer: Signer<Uint8Array>): HcsDidTransaction {
        this.signer = signer;
        return this;
    }

    /**
     * Sets {@link TopicMessageSubmitTransaction} parameters, builds and signs it without executing it.
     * Topic ID and transaction message content are already set in the incoming transaction.
     *
     * @param builderFunction The transaction builder function.
     * @return This transaction instance.
     */
    public buildAndSignTransaction(
        builderFunction: (input: TopicMessageSubmitTransaction) => Promise<Transaction>
    ): HcsDidTransaction {
        this.buildTransactionFunction = builderFunction;
        return this;
    }

    /**
     * Builds the message and submits it to appnet's topic.
     *
     * @param client The hedera network client.
     * @return Transaction ID.
     */
    public async execute(client: Client): Promise<TransactionId> {
        new Validator().checkValidationErrors("MessageTransaction execution failed: ", (v) => {
            return this.validate(v);
        });

        const envelope = this.message;
        const messageContent = !envelope.getSignature()
            ? envelope.sign(this.signer!) // Ensure `signer` exists with `!`
            : ArraysUtils.fromString(envelope.toJSON());

        const tx = new TopicMessageSubmitTransaction().setTopicId(this.topicId).setMessage(messageContent);
        let transactionId: TransactionId | undefined;
        try {
            if (this.buildTransactionFunction) {
                const response = await (await this.buildTransactionFunction(tx)).execute(client);
                await response.getReceipt(client);
                transactionId = response.transactionId;
                this.executed = true;
            }
        } catch (e) {
            this.handleError(e as Error);
        }

        if (!transactionId) {
            throw new DidError("Transaction ID is undefined after execution");
        }
        return transactionId;
    }

    /**
     * Runs validation logic.
     *
     * @param validator The errors validator.
     */
    protected validate(validator: Validator): void {
        validator.require(!this.executed, "This transaction has already been executed.");
        validator.require(
            !!this.signer || (!!this.message && !!this.message.getSignature()),
            "Signing function is missing."
        );
        validator.require(!!this.buildTransactionFunction, "Transaction builder is missing.");
    }
}
