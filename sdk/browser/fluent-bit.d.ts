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
    /** Characters kept of one stdout or stderr line, 4096 (default) to 1048576.
     * `otlp_json` prints a whole export request as one line. */
    outputLineLimit?: number;
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
    /** Optional methods this runtime supports; check before calling them. */
    readonly features: readonly FluentBitFeature[];
}
export type FluentBitFeature = 'condition' | 'topology' | 'trace' | 'otlp';
export type FluentBitSignal = 'logs' | 'metrics' | 'traces';
/** One instance as the engine created it; `index` is its position in the configuration. */
export interface FluentBitInstance {
    readonly index: number;
    /** Instance name, such as `stdout.0`. */
    readonly name: string;
    readonly plugin: string;
    readonly alias: string | null;
}
export interface FluentBitRouteOutput {
    /** Name written in the route. */
    readonly requested: string;
    readonly fallback: string | null;
    /** Output index the name resolved to, if any. */
    readonly resolved: number | null;
    readonly usedFallback: boolean;
    /** `already_connected`: an earlier route of the input owns the connection. */
    readonly status: 'connected' | 'already_connected' | 'not_found' |
        'signal_not_supported' | 'connect_failed' | 'pending';
}
export interface FluentBitRoute {
    readonly name: string;
    readonly signals: readonly FluentBitSignal[];
    readonly conditional: boolean;
    readonly isDefault: boolean;
    readonly perRecord: boolean;
    /** True when records are split per route and re-tagged with the route name. */
    readonly split: boolean;
    readonly outputs: readonly FluentBitRouteOutput[];
}
export interface FluentBitTopology {
    readonly inputs: readonly (FluentBitInstance & {
        readonly tag: string | null;
        /** Outputs whose match selected the configured tag. */
        readonly matchedOutputs: readonly number[];
        /** Outputs connected by routes; when present they replace tag matching. */
        readonly directOutputs: readonly number[];
        readonly routes: readonly FluentBitRoute[];
    })[];
    readonly filters: readonly (FluentBitInstance & {
        readonly match: string | null;
        readonly matchRegex: boolean;
        /** Inputs whose configured tag the filter selects. */
        readonly matchesInputs: readonly number[];
    })[];
    readonly outputs: readonly (FluentBitInstance & {
        readonly match: string | null;
        readonly matchRegex: boolean;
    })[];
}
/** `record` is the position among the log records of the chunk named by `append`. */
export type FluentBitTraceEvent =
    {stage: 'append'; append: number; input: number; tag: string; records: number} |
    {stage: 'route'; append: number; record: number; input: number; route: string; isDefault: boolean} |
    {stage: 'unrouted'; append: number; record: number; input: number} |
    {stage: 'filter'; input: number; tag: string; filter: number;
     recordsIn: number; recordsOut: number; modified: boolean} |
    {stage: 'output'; input: number; tag: string; output: number; records: number} |
    {stage: 'undelivered'; input: number; tag: string; records: number};
export interface FluentBit {
    readonly state: FluentBitState;
    readonly info: FluentBitInfo;
    /** Lifetime SDK counters; acceptance is not delivery. Includes this queued query. */
    getStats(): Promise<FluentBitStats>;
    /** Resolves at actual engine readiness; graceSeconds overrides YAML grace. */
    start(options: {yaml: string; graceSeconds?: number; trace?: boolean}): Promise<{engineMs: number}>;
    /** Which sample log records a route `condition` takes, decided by the engine.
     * Needs no running pipeline. Rejects with E_CONDITION and the engine's reason. */
    evaluateCondition(options: {condition: Record<string, unknown>;
        records: Record<string, unknown>[]; metadata?: (Record<string, unknown> | null)[]}):
        Promise<{readonly matched: readonly boolean[]}>;
    /** Connections the running engine made: routes, fallbacks and tag matches. */
    getTopology(): Promise<FluentBitTopology>;
    /** Decisions recorded since the last call, for a start with `trace: true`.
     * Call after drain(). `dropped` counts events beyond the trace limit. */
    takeTrace(): Promise<{events: FluentBitTraceEvent[]; dropped: number}>;
    /** Quiesces the engine and checkpoints persistent chunks; not a delivery guarantee. */
    stop(): Promise<void>;
    /** Flushes queued engine chunks and invokes stdout/stderr callbacks before resolving.
     * Promises returned by callbacks are not awaited. Requires memory-backed
     * lib inputs and stdout/null outputs; filter/processor-private buffers are excluded. */
    drain(): Promise<void>;
    /** Input alias must select one lib input. Records receive an ingestion timestamp. */
    push(options: {input: string; records: Record<string, unknown>[]}):
        Promise<{acceptedBytes: number; acceptedRecords: number}>;
    /** One OTLP/JSON export request (`resourceMetrics` or `resourceSpans`) for a lib
     * input, decoded by the engine; the input's processors run before this resolves.
     * Text is passed as written. Needs the `otlp` feature; a payload the engine
     * cannot decode rejects with E_ARGUMENT. */
    pushOtlp(options: {input: string; signal: 'metrics' | 'traces';
        payload: string | Record<string, unknown>}): Promise<{acceptedBytes: number}>;
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
