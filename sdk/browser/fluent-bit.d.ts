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
    /** Input alias must select one lib input. Records receive an ingestion timestamp. */
    push(options: {input: string; records: Record<string, unknown>[]}):
        Promise<{acceptedBytes: number; acceptedRecords: number}>;
    /** Assets beneath /config/ only; engine must be stopped. */
    writeFile(path: string, data: string | Uint8Array): Promise<void>;
    readFile(path: string): Promise<Uint8Array>;
    /** Engine must be stopped. Also retries a failed stop-time checkpoint. */
    syncStorage(): Promise<void>;
    /** Idempotent. Force terminates immediately and can lose unflushed data. */
    destroy(options?: {force?: boolean}): Promise<void>;
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
