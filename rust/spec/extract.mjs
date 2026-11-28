#!/usr/bin/env node
// Derive an RFC's requirement sentences from its pinned plain text: `node spec/extract.mjs <rfcNNNN.txt>` prints the JSON that
// rust/spec/rfcNNNN.json holds (`just spec-extract <dir>` compares the two). A requirement is a sentence, in any section, holding
// MUST, MUST NOT, REQUIRED, SHALL or SHALL NOT in capitals; the one BCP 14 boilerplate sentence that lists the key words is not one.
// Page footers and headers are dropped, a paragraph's lines are joined with one space (a line ending in a letter and `-` joins with none), and a
// sentence ends at a `.` followed by whitespace and a capital, a quote or `(`. claims.mjs compares citations with these sentences.
// Out of scope: a sentence holding only SHOULD, SHOULD NOT or RECOMMENDED (9 in RFC 7515, 1 in RFC 7516, 10 in RFC 7517, 10 in RFC 7518,
// 9 in RFC 7519 by this splitter); one that also holds an in-scope word is kept (RFC 7515 10.13). A keyword in quotes counts: RFC 7515 4 (designated
// "MUST be understood") and 10.12 (the "SHOULD" treated as a "MUST") are requirements on the implementation.
// Licence of this script: MIT OR Apache-2.0.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename } from 'node:path';

const src = process.argv[2];
const m = src && /^rfc(\d+)\.txt$/.exec(basename(src));
if (!m) {
    console.error('usage: extract.mjs <path>/rfcNNNN.txt');
    process.exit(2);
}
const bytes = readFileSync(src);
const lines = [];
let footer = false;
for (const l of bytes.toString('utf8').replace(/\r/g, '').split('\n')) {
    if (/\[Page \d+\]\s*$/.test(l)) {
        // a footer and the blank lines around it are transparent to the paragraph it interrupts
        while (lines.at(-1) === '') lines.pop();
        footer = true;
        continue;
    }
    if (footer && (l === '' || /^\f?RFC \d+ /.test(l) || l === '\f')) continue;
    footer = false;
    lines.push(l);
}
const HEADING = /^(?:Appendix )?(\d+(?:\.\d+)*|[A-Z](?:\.\d+)*)\.\s+\S/;
const KEYWORD = /\b(?:MUST|REQUIRED|SHALL)\b/;
const BOILERPLATE = /^The key words "MUST", .* are to be interpreted as described in/;
const requirements = [];
let section = null;
let para = [];
const flush = () => {
    if (section !== null && para.length) {
        const text = para.reduce((a, l) => (/[A-Za-z]-$/.test(a) ? a + l : `${a} ${l}`)).replace(/\s+/g, ' ');
        for (const s of text.split(/(?<=\.)\s+(?=[A-Z"(])/)) {
            if (KEYWORD.test(s) && !BOILERPLATE.test(s) && !requirements.some((r) => r.section === section && r.text === s)) requirements.push({ section, text: s });
        }
    }
    para = [];
};
for (const l of lines) {
    const h = HEADING.exec(l);
    if (h) {
        flush();
        section = h[1];
    } else if (l.trim() === '') flush();
    else if (section !== null) para.push(l.trim());
}
flush();
const out = {
    rfc: +m[1],
    source: `https://www.rfc-editor.org/rfc/rfc${m[1]}.txt`,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    licence: 'IETF Trust (quoted RFC text)',
    requirements,
};
process.stdout.write(`${JSON.stringify(out, null, 1)}\n`);
