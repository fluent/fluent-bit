/* SPDX-License-Identifier: Apache-2.0 */
/* Network inputs fed by the page: the host program supplies what a socket would. */
(async () => {
    const {createFluentBit} = await import('/sdk/fluent-bit.js');
    const logs = [];
    const fluent = await createFluentBit({onStdout: line => logs.push(line),
        onStderr: line => logs.push(line)});
    const check = (condition, message) => { if (!condition) { throw new Error(message); } };
    const rejected = async (action, code) => {
        try { await action(); }
        catch (error) { check(error.code === code, `${code}: got ${error.code}: ${error.message}`); return; }
        throw new Error(`Expected ${code}`);
    };
    const waitFor = async (predicate, what) => {
        for (let i = 0; i < 400; i++) {
            if (await predicate()) { return; }
            await new Promise(resolve => setTimeout(resolve, 25));
        }
        throw new Error(`Timed out waiting for ${what}`);
    };
    const records = () => logs.flatMap(line => {
        try { return [JSON.parse(line)]; }
        catch (_) { return []; }
    });
    const text = body => new TextDecoder().decode(body);
    const yaml = `service:
  flush: 0.1
  log_level: info
pipeline:
  inputs:
    - name: tcp
      alias: stream
      tag: stream
      source.mode: external
      format: json
    - name: tcp
      alias: lines
      tag: lines
      source.mode: external
      format: none
      chunk_size: 1
      buffer_size: 2
    - name: http
      alias: web
      tag: web
      source.mode: external
    - name: opentelemetry
      alias: otlp
      tag: otlp
      source.mode: external
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
`;
    const otlpLogs = JSON.stringify({resourceLogs: [{scopeLogs: [{logRecords: [
        {timeUnixNano: '1660296023390371588', body: {stringValue: 'browser otlp json'}}]}]}]});
    // ExportLogsServiceRequest with one record whose body is "browser otlp proto".
    const protoBody = new TextEncoder().encode('browser otlp proto');
    const otlpProto = new Uint8Array([0x0a, protoBody.length + 8, 0x12, protoBody.length + 6,
        0x12, protoBody.length + 4, 0x2a, protoBody.length + 2, 0x0a, protoBody.length, ...protoBody]);
    try {
        await rejected(() => fluent.pushBytes({input: 'stream', data: '{}'}), 'E_STATE');
        await rejected(() => fluent.request({input: 'web', path: '/'}), 'E_STATE');
        await fluent.start({yaml, graceSeconds: 1});

        // Byte stream: a call is not a record boundary, multi-byte text included.
        const stream = new TextEncoder().encode('{"message":"browser café ☃ stream"}{"second":2}');
        for (let offset = 0; offset < stream.byteLength; offset += 7) {
            const accepted = await fluent.pushBytes({input: 'stream',
                                                     data: stream.subarray(offset, offset + 7)});
            check(accepted.acceptedBytes === Math.min(7, stream.byteLength - offset), 'Accepted bytes');
        }
        await waitFor(() => records().some(record => record.message === 'browser café ☃ stream') &&
                            records().some(record => record.second === 2), 'stream records');
        await rejected(() => fluent.pushBytes({input: 'absent', data: 'x'}), 'E_INPUT');
        // A lib input is not in external mode, and a stream input takes no requests.
        await rejected(() => fluent.request({input: 'stream', path: '/'}), 'E_UNSUPPORTED');
        await rejected(() => fluent.pushBytes({input: 'web', data: 'x'}), 'E_UNSUPPORTED');

        // One call far larger than Buffer_Size made of small records is accepted.
        // Kept below the SDK log batch limit so no stdout line is dropped.
        const many = Array.from({length: 100},
            (_, index) => `line ${index} ${'x'.repeat(48)}\n`).join('');
        check(many.length > 2 * 2048, 'Submission exceeds Buffer_Size');
        await fluent.pushBytes({input: 'lines', data: many});
        await waitFor(() => records().filter(record => /^line \d+ x+$/.test(record.log)).length === 100,
                      'line records');
        // A single record larger than Buffer_Size ends that stream, not the others.
        await fluent.pushBytes({input: 'lines', data: 'z'.repeat(8192)});
        await waitFor(async () => {
            try { await fluent.pushBytes({input: 'lines', data: 'later\n'}); return false; }
            catch (error) { return error.code === 'E_STREAM_FAILED'; }
        }, 'failed stream');
        await fluent.pushBytes({input: 'stream', data: '{"after":"failure"}'});
        await waitFor(() => records().some(record => record.after === 'failure'), 'healthy stream');

        // Requests: the reply is the response of the input handler.
        const created = await fluent.request({input: 'web', path: '/app.logs?source=page',
            headers: {'Content-Type': 'application/json'}, body: '{"message":"browser http"}'});
        check(created.status === 201 && created.truncated === false && Object.isFrozen(created),
              `HTTP input reply: ${created.status}`);
        check(created.headers.some(header => header[0] === 'content-length' && header[1] === '0'),
              'Reply headers');
        await waitFor(() => records().some(record => record.message === 'browser http'), 'http record');
        const refused = await fluent.request({input: 'web', path: '/',
            headers: {'Content-Type': 'application/json'}, body: '{"broken":'});
        check(refused.status === 400 && text(refused.body).startsWith('error:'),
              `Decoder error reply: ${refused.status} ${text(refused.body)}`);
        const grpc = await fluent.request({input: 'web', path: '/',
            headers: {'Content-Type': 'application/grpc'}, body: 'x'});
        check(grpc.status === 415, `gRPC is refused: ${grpc.status}`);

        // OTLP: path and content type select the signal and the decoder.
        const json = await fluent.request({input: 'otlp', path: '/v1/logs',
            headers: {'Content-Type': 'application/json'}, body: otlpLogs});
        check(json.status === 201, `OTLP JSON reply: ${json.status} ${text(json.body)}`);
        const proto = await fluent.request({input: 'otlp', path: '/v1/logs',
            headers: {'Content-Type': 'application/x-protobuf'}, body: otlpProto});
        check(proto.status === 201, `OTLP Protobuf reply: ${proto.status} ${text(proto.body)}`);
        await waitFor(() => logs.some(line => line.includes('browser otlp json')) &&
                            logs.some(line => line.includes('browser otlp proto')), 'OTLP records');
        const missing = await fluent.request({input: 'otlp', path: '/v1/unknown',
            headers: {'Content-Type': 'application/json'}, body: otlpLogs});
        check(missing.status === 404, `OTLP unknown path: ${missing.status}`);

        // Concurrent requests are answered one by one, each with its own reply.
        const replies = await Promise.all(Array.from({length: 8}, (_, index) =>
            fluent.request({input: 'web', path: `/batch.${index}`,
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({batch: index})})));
        check(replies.every(reply => reply.status === 201), 'Concurrent replies');
        await waitFor(() => records().filter(record => Number.isInteger(record.batch)).length === 8,
                      'batch records');

        check((await fluent.getStats()).acceptedBytes > stream.byteLength, 'Accepted byte counter');
        await rejected(() => fluent.drain(), 'E_UNSUPPORTED');
        await fluent.stop();
        check(fluent.state === 'stopped', 'Stopped');

        // A restart gives a failed stream a new start.
        await fluent.start({yaml, graceSeconds: 0});
        await fluent.pushBytes({input: 'lines', data: 'restarted\n'});
        await waitFor(() => records().some(record => record.log === 'restarted'), 'restarted stream');
        await fluent.stop();
        return {passed: true, inputs: ['tcp', 'http', 'opentelemetry'], logs};
    }
    catch (error) { throw new Error(`${error.message}\n${logs.join("\n")}`); }
    finally { await fluent.destroy(); }
})()
