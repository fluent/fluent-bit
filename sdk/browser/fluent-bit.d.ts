export const SDK_VERSION: '0.1.0-experimental';
export type FluentBitState = 'loading' | 'ready' | 'starting' | 'running' |
    'stopping' | 'stopped' | 'failed' | 'destroyed';
export class FluentBitError extends Error {
    constructor(code: string, message: string);
    readonly code: string;
}
export interface FluentBitOptions {
    workerUrl?: string | URL;
    /** Cancels initialization only. Use stop/destroy after initialization. */
    signal?: AbortSignal;
    initTimeoutMs?: number;
    operationTimeoutMs?: number;
    destroyTimeoutMs?: number;
    storage?: {persistent?: false} | {persistent: true; namespace: string};
    onStdout?: (line: string) => void;
    onStderr?: (line: string) => void;
    onStateChange?: (state: FluentBitState) => void;
    onError?: (error: FluentBitError) => void;
    onProgress?: (progress: FluentBitProgress) => void;
}
export interface FluentBitProgress {
    readonly stage: 'loading-runtime' | 'downloading-wasm' | 'compiling-wasm' |
        'initializing-workers' | 'starting-command-thread';
    readonly loadedBytes: number;
    /** Zero when the decoded size is unknown, including compressed responses. */
    readonly totalBytes: number;
}
export interface FluentBitInfo {
    readonly abi: number;
    readonly engineVersion: string;
    readonly sdkVersion: string;
    readonly storagePath: string;
    readonly persistent: boolean;
}
export interface FluentBit {
    readonly state: FluentBitState;
    readonly info: FluentBitInfo;
    /** Lifetime SDK counters; acceptance is not delivery. Includes this queued query. */
    getStats(): Promise<FluentBitStats>;
    /** Resolves at actual engine readiness; graceSeconds overrides YAML grace. */
    start(options: {yaml: string; graceSeconds?: number}): Promise<{engineMs: number}>;
    /** Quiesces the engine and checkpoints persistent chunks; not a delivery guarantee. */
    stop(): Promise<void>;
    /** Flushes queued engine chunks and invokes stdout/stderr callbacks before resolving.
     * Promises returned by callbacks are not awaited. Requires memory-backed
     * lib inputs and stdout/null outputs; filter/processor-private buffers are excluded. */
    drain(): Promise<void>;
    /** Input alias must select one lib input. Records receive an ingestion timestamp. */
    push(options: {input: string; records: Record<string, unknown>[]}):
        Promise<{acceptedBytes: number; acceptedRecords: number}>;
    /** Feeds bytes to an input configured with `source.mode: external` that reads a
     * byte stream, such as tcp. A call is not a record boundary. Resolves when the
     * bytes are queued, not when they are parsed. E_BACKPRESSURE means nothing was
     * taken: submit the same bytes again, different bytes would leave a gap. */
    pushBytes(options: {input: string; data: string | Uint8Array}):
        Promise<{acceptedBytes: number}>;
    /** Submits one request to an HTTP input configured with `source.mode: external`
     * and resolves with the reply of the input. Method defaults to POST and a Host
     * header is added when absent. Rejects with E_REQUEST_FAILED when the input
     * processed the request without a reply (do not submit it again) and with
     * E_STOPPED when the engine stopped first. A reply is not a delivery guarantee. */
    request(options: FluentBitRequest): Promise<FluentBitReply>;
    /** Assets beneath /config/ only; engine must be stopped. */
    writeFile(path: string, data: string | Uint8Array): Promise<void>;
    readFile(path: string): Promise<Uint8Array>;
    /** Engine must be stopped. Also retries a failed stop-time checkpoint. */
    syncStorage(): Promise<void>;
    /** Idempotent. Force terminates immediately and can lose unflushed data. */
    destroy(options?: {force?: boolean}): Promise<void>;
}
export interface FluentBitRequest {
    input: string;
    method?: string;
    /** Starts with "/" and may carry a query string. */
    path: string;
    headers?: Record<string, string> | [string, string][];
    body?: string | Uint8Array;
}
export interface FluentBitReply {
    readonly status: number;
    readonly headers: readonly (readonly [string, string])[];
    readonly body: Uint8Array;
    /** True when the body did not fit the 64 KiB reply limit. */
    readonly truncated: boolean;
}
export interface FluentBitStats {
    readonly state: FluentBitState;
    readonly wasmMemoryBytes: number;
    readonly activeHttpRequests: number;
    readonly acceptedBytes: number;
    readonly acceptedRecords: number;
    readonly queuedCommands: number;
    readonly queuedBytes: number;
    readonly rejectedCommands: number;
    readonly droppedLogLines: number;
    readonly checkpointRequired: boolean;
    readonly checkpointFailures: number;
    /** Successful persistent checkpoint time in epoch milliseconds, otherwise null. */
    readonly lastCheckpointTime: number | null;
}
export function createFluentBit(options?: FluentBitOptions): Promise<FluentBit>;
export function getBrowserSupport(): {supported: boolean; missing: string[]};
