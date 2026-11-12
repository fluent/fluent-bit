/* SPDX-License-Identifier: Apache-2.0 */
(async () => {
    const {createFluentBit} = await import('/sdk/fluent-bit.js');
    const logs = [];
    const fluent = await createFluentBit({onStdout: line => logs.push(line),
        onStderr: line => logs.push(line)});
    const waitFor = async predicate => {
        for (let i = 0; i < 400; i++) {
            if (await predicate()) { return; }
            await new Promise(resolve => setTimeout(resolve, 25));
        }
        throw new Error(`Plugin delivery timed out: ${logs.join('\n')}`);
    };
    try {
        await fluent.writeFile('/config/head.txt', 'browser head fixture\n');
        await fluent.writeFile('/config/tail.log', 'browser tail fixture\n');
        const utf16 = 'browser UTF-16 café fixture\n';
        const bytes = new Uint8Array(utf16.length * 2);
        const view = new DataView(bytes.buffer);
        for (let i = 0; i < utf16.length; i++) {
            view.setUint16(i * 2, utf16.charCodeAt(i), true);
        }
        await fluent.writeFile('/config/utf16.log', bytes);
        await fluent.writeFile('/config/browser.prom', '# TYPE browser_fixture gauge\nbrowser_fixture 42\n');
        await fluent.start({yaml: `service:
  flush: 0.1
  log_level: error
pipeline:
  inputs:
    - name: head
      file: /config/head.txt
      interval_sec: 1
      tag: files
    - name: tail
      path: /config/tail.log
      db: /config/tail.db
      read_from_head: true
      refresh_interval: 1
      tag: files
    - name: tail
      path: /config/utf16.log
      unicode.encoding: UTF-16LE
      read_from_head: true
      refresh_interval: 1
      tag: files
    - name: prometheus_textfile
      threaded: false
      path: /config/browser.prom
      scrape_interval: 1
      tag: metrics
  outputs:
    - name: stdout
      match: '*'
      format: json_lines
    - name: file
      match: files
      path: /config
      file: exported.log
      format: plain
      workers: 0
`, graceSeconds: 1});
        await waitFor(() => logs.some(line => line.includes('browser head fixture')) &&
            logs.some(line => line.includes('browser tail fixture')) &&
            logs.some(line => {
                try { return JSON.parse(line).log === 'browser UTF-16 café fixture'; }
                catch (_) { return false; }
            }) &&
            logs.some(line => line.includes('browser_fixture')));
        await fluent.stop();
        const file = new TextDecoder().decode(await fluent.readFile('/config/exported.log'));
        if (!file.includes('browser head fixture') || !file.includes('browser tail fixture') ||
            !file.split('\n').some(line => {
                try { return JSON.parse(line).log === 'browser UTF-16 café fixture'; }
                catch (_) { return false; }
            })) {
            throw new Error(`File output lost records: ${file}`);
        }
        const database = await fluent.readFile('/config/tail.db');
        if (new TextDecoder().decode(database.slice(0, 15)) !== 'SQLite format 3') {
            throw new Error('Tail did not create a SQLite database');
        }
        const esToken = crypto.randomUUID();
        const ddToken = crypto.randomUUID();
        await fluent.start({yaml: `service:
  flush: 0.1
  log_level: error
pipeline:
  inputs:
    - name: lib
      alias: app
  outputs:
    - name: es
      match: '*'
      browser.url: ${location.origin}/collect/${esToken}
      workers: 0
    - name: datadog
      match: '*'
      apikey: browser-test-key
      browser.url: ${location.origin}/collect/${ddToken}
      workers: 0
`, graceSeconds: 1});
        await fluent.push({input: 'app', records: [{message: 'browser HTTP plugin fixture'}]});
        for (const token of [esToken, ddToken]) {
            await waitFor(async () => {
                const result = await (await fetch(`/received/${token}`)).json();
                return result.requests.some(request =>
                    request.body.includes('browser HTTP plugin fixture'));
            });
        }
        await fluent.stop();
        return {passed: true, plugins: ['head', 'tail', 'prometheus_textfile', 'file',
            'es', 'datadog'], logs};
    }
    catch (error) { throw new Error(`${error.message}\n${logs.join("\n")}`); }
    finally { await fluent.destroy(); }
})()
