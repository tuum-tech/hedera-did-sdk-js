import { Timestamp, TopicId } from "@hashgraph/sdk";
import { DidError } from "../../did-error";
import { MessageEnvelope } from "../message-envelope";
import { HcsDidMessage } from "./hcs-did-message";

/**
 * A listener of confirmed {@link HcsDidMessage} messages from a DID topic.
 * Messages are received from the mirror node API, parsed, and validated.
 */
export class HcsDidTopicListener {
    protected topicId: TopicId;
    protected errorHandler: ((input: Error) => void) | undefined;
    protected ignoreErrors: boolean;
    protected filters: ((input: any) => boolean)[] = [];
    protected invalidMessageHandler: ((t: any, u: string) => void) | undefined;
    protected baseUrl: string;

    /**
     * Creates a new instance of a DID topic listener for the given consensus topic.
     * By default, invalid messages are ignored and errors are not.
     *
     * @param topicId The DID consensus topic ID.
     * @param baseUrl The base URL of the mirror node API.
     */
    constructor(topicId: TopicId, baseUrl: string, startTime: Timestamp = new Timestamp(0, 0)) {
        this.topicId = topicId;
        this.ignoreErrors = false;
        this.baseUrl = baseUrl;
    }

    /**
     * Adds a custom filter for topic responses from the mirror node.
     * Messages that do not pass the test are skipped before any other checks are run.
     *
     * @param filter The filter function.
     * @return This listener instance.
     */
    public addFilter(filter: (input: any) => boolean): HcsDidTopicListener {
        if (!this.filters) {
            this.filters = [];
        }
        this.filters.push(filter);
        return this;
    }

    /**
     * Fetches messages from the mirror node topic messages endpoint.
     *
     * @param receiver Receiver of parsed messages.
     * @return This listener instance.
     */
    public async subscribe(receiver: (input: MessageEnvelope<HcsDidMessage>) => void): Promise<HcsDidTopicListener> {
        const endpoint = `${this.baseUrl}/api/v1/topics/${this.topicId.toString()}/messages`;
        try {
            const response = await fetch(endpoint);
            if (!response.ok) {
                throw new Error(`Failed to fetch messages: ${response.statusText}`);
            }

            const data = await response.json();
            const messages = data.messages || [];
            for (const message of messages) {
                this.handleResponse(message, receiver);
            }
        } catch (error) {
            this.handleError(error as Error);
        }
        return this;
    }

    /**
     * Handles incoming messages from the mirror node API.
     *
     * @param response Response message coming from the mirror node for the topic.
     * @param receiver Consumer of the result message.
     */
    protected handleResponse(response: any, receiver: (input: MessageEnvelope<HcsDidMessage>) => void): void {
        if (this.filters) {
            for (const filter of this.filters) {
                if (!filter(response)) {
                    this.reportInvalidMessage(response, "Message was rejected by external filter");
                    return;
                }
            }
        }

        const envelope = this.extractMessage(response);

        if (!envelope) {
            this.reportInvalidMessage(response, "Extracting envelope from the response failed");
            return;
        }

        if (this.isMessageValid(envelope, response)) {
            receiver(envelope);
        }
    }

    /**
     * Extracts and parses the message inside the response object into the given type.
     *
     * @param response Response message from the mirror node API.
     * @return The message inside an envelope.
     */
    protected extractMessage(response: any): MessageEnvelope<HcsDidMessage> | null {
        let result: MessageEnvelope<HcsDidMessage> | null = null;
        try {
            // Decode the Base64-encoded response.message
            const decodedMessage = Buffer.from(response.message, "base64").toString("utf-8");
            const parsedMessage = JSON.parse(decodedMessage);

            // Decode the Base64-encoded event if necessary
            if (parsedMessage?.message?.event) {
                try {
                    const decodedEvent = Buffer.from(parsedMessage.message.event, "base64").toString("utf-8");
                    parsedMessage.message.event = JSON.parse(decodedEvent); // Parse the JSON-encoded `event`
                } catch (eventDecodeError) {
                    console.error("Failed to decode event field: ", eventDecodeError); // Log event-specific errors
                    throw new DidError("Failed to decode and parse event field");
                }
            }

            // Construct HcsDidMessage with the parsed message object
            const hcsDidMessage = HcsDidMessage.fromJsonTree(parsedMessage.message);
            result = new MessageEnvelope<HcsDidMessage>(hcsDidMessage);
            result.setSignature(parsedMessage.signature);
        } catch (err) {
            console.error("Error in extractMessage: ", err); // Log full error details
            this.handleError(err as Error);
        }
        return result;
    }

    /**
     * Validates the message and its envelope signature.
     *
     * @param envelope The message inside an envelope.
     * @param response Response message from the mirror node API.
     * @return True if the message is valid, False otherwise.
     */
    protected isMessageValid(envelope: MessageEnvelope<HcsDidMessage>, response: any): boolean {
        try {
            const message: HcsDidMessage | null = envelope.open();
            if (message === null) {
                this.reportInvalidMessage(response, "Empty message received when opening envelope");
                return false;
            }

            if (!message.isValid(this.topicId)) {
                this.reportInvalidMessage(response, "Message content validation failed.");
                return false;
            }

            return true;
        } catch (err) {
            this.handleError(err as Error);
            this.reportInvalidMessage(response, "Exception while validating message: " + (err as Error).message);
            return false;
        }
    }

    /**
     * Handles the given error internally.
     * If external error handler is defined, passes the error there, otherwise raises DidError or ignores it
     * depending on a ignoreErrors flag.
     *
     * @param err The error.
     */
    protected handleError(err: Error): void {
        if (this.errorHandler) {
            this.errorHandler(err);
        } else if (!this.ignoreErrors) {
            throw new DidError(err.message);
        }
    }

    /**
     * Reports invalid message to the handler.
     *
     * @param response The mirror response.
     * @param reason   The reason why message validation failed.
     */
    protected reportInvalidMessage(response: any, reason: string): void {
        if (this.invalidMessageHandler) {
            this.invalidMessageHandler(response, reason);
        }
    }

    /**
     * Defines a handler for errors when they happen during execution.
     *
     * @param handler The error handler.
     * @return This transaction instance.
     */
    public onError(handler: (input: Error) => void): HcsDidTopicListener {
        this.errorHandler = handler;
        return this;
    }

    /**
     * Defines a handler for invalid messages received from the topic.
     *
     * @param handler The invalid message handler.
     * @return This transaction instance.
     */
    public onInvalidMessageReceived(handler: (t: any, u: string) => void): HcsDidTopicListener {
        this.invalidMessageHandler = handler;
        return this;
    }

    public setIgnoreErrors(ignoreErrors: boolean): HcsDidTopicListener {
        this.ignoreErrors = ignoreErrors;
        return this;
    }
}
