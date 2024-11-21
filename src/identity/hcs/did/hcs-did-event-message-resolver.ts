import { Timestamp, TopicId } from "@hashgraph/sdk";
import Long from "long";
import { Validator } from "../../../utils/validator";
import { MessageEnvelope } from "../message-envelope";
import { HcsDidMessage } from "./hcs-did-message";
import { HcsDidTopicListener } from "./hcs-did-topic-listener";

/**
 * Resolves the DID Events from the Hedera network using the Mirror Node REST API.
 */
export class HcsDidEventMessageResolver {
    /**
     * Default time to wait before finishing resolution and after the last message was received.
     */
    public static DEFAULT_TIMEOUT: Long = Long.fromInt(30000);

    protected topicId: TopicId;
    protected messages: MessageEnvelope<HcsDidMessage>[] = [];
    private lastMessageArrivalTime: Long;
    private nextMessageArrivalTimeout: NodeJS.Timeout | undefined;
    private resultsHandler: ((input: MessageEnvelope<HcsDidMessage>[]) => void) | undefined;
    private errorHandler: ((input: Error) => void) | undefined;
    private existingSignatures: string[] = [];
    private readonly listener: HcsDidTopicListener;
    private noMoreMessagesTimeout: Long;

    /**
     * Instantiates a new DID resolver for the given DID topic.
     *
     * @param topicId The HCS DID topic ID.
     * @param baseUrl The base URL of the mirror node API.
     * @param startTime Optional start time for the listener.
     */
    constructor(topicId: TopicId, baseUrl: string, startTime: Timestamp = new Timestamp(0, 0)) {
        this.topicId = topicId;
        this.listener = new HcsDidTopicListener(this.topicId, baseUrl, startTime);

        this.noMoreMessagesTimeout = HcsDidEventMessageResolver.DEFAULT_TIMEOUT;
        this.lastMessageArrivalTime = Long.fromInt(Date.now());
    }

    /**
     * Executes the message resolution process.
     */
    public async execute(): Promise<void> {
        new Validator().checkValidationErrors("Resolver not executed: ", (v) => {
            return this.validate(v);
        });

        this.existingSignatures = [];

        try {
            await this.listener
                .setIgnoreErrors(false)
                .onError(this.errorHandler || ((err) => console.error("Error:", err)))
                .subscribe((msg) => {
                    this.handleMessage(msg);
                });

            this.lastMessageArrivalTime = Long.fromInt(Date.now());
            await this.waitOrFinish();
        } catch (error) {
            if (this.errorHandler) {
                this.errorHandler(error as Error);
            }
        }
    }

    /**
     * Handles incoming DID messages from the topic.
     *
     * @param envelope The parsed message envelope.
     */
    private handleMessage(envelope: MessageEnvelope<HcsDidMessage>): void {
        this.lastMessageArrivalTime = Long.fromInt(Date.now());

        const message = envelope.open();
        if (message === null || !this.matchesSearchCriteria(message)) {
            return;
        }
        if (this.existingSignatures.indexOf(envelope.getSignature()) !== -1) {
            return;
        }

        this.existingSignatures.push(envelope.getSignature());
        this.messages.push(envelope);
    }

    /**
     * Waits for new messages or finishes if the timeout is exceeded.
     */
    protected async waitOrFinish(): Promise<void> {
        const timeDiff = Long.fromInt(Date.now()).sub(this.lastMessageArrivalTime);

        if (timeDiff.lessThanOrEqual(this.noMoreMessagesTimeout)) {
            if (this.nextMessageArrivalTimeout) {
                clearTimeout(this.nextMessageArrivalTimeout);
            }
            this.nextMessageArrivalTimeout = setTimeout(
                () => this.waitOrFinish(),
                this.noMoreMessagesTimeout.sub(timeDiff).toNumber()
            );
            return;
        }

        await this.finish();
    }

    /**
     * Finalizes the resolution process and calls the results handler.
     */
    protected async finish(): Promise<void> {
        if (this.resultsHandler) {
            this.resultsHandler(this.messages);
        }

        if (this.nextMessageArrivalTimeout) {
            clearTimeout(this.nextMessageArrivalTimeout);
        }
    }

    /**
     * Defines a handler for resolution results.
     * This will be called when the resolution process is finished.
     *
     * @param handler The results handler.
     * @return This resolver instance.
     */
    public whenFinished(handler: (input: MessageEnvelope<HcsDidMessage>[]) => void): HcsDidEventMessageResolver {
        this.resultsHandler = handler;
        return this;
    }

    /**
     * Defines a handler for errors when they happen during resolution.
     *
     * @param handler The error handler.
     * @return This resolver instance.
     */
    public onError(handler: (input: Error) => void): HcsDidEventMessageResolver {
        this.errorHandler = handler;
        return this;
    }

    /**
     * Defines a maximum time in milliseconds to wait for new messages from the topic.
     * Default is 30 seconds.
     *
     * @param timeout The timeout in milliseconds.
     * @return This resolver instance.
     */
    public setTimeout(timeout: Long | number): HcsDidEventMessageResolver {
        this.noMoreMessagesTimeout = Long.fromValue(timeout);
        return this;
    }

    /**
     * Runs validation logic of the resolver's configuration.
     *
     * @param validator The errors validator.
     */
    protected validate(validator: Validator): void {
        validator.require(!!this.topicId, "Consensus topic ID not defined.");
        validator.require(!!this.resultsHandler, "Results handler 'whenFinished' not defined.");
    }

    /**
     * Checks if a message matches the search criteria.
     *
     * @param message The message to check.
     * @return True if the message matches; otherwise, false.
     */
    protected matchesSearchCriteria(message: HcsDidMessage): boolean {
        return true;
    }
}
