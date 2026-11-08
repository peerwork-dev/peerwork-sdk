// Direct Node 24 / ICU baseline for the historical composeProtocol
// localeCompare comparator. These strings never leave this conformance input.
import {writeFileSync} from 'node:fs';

if (process.versions.node !== '24.20.0' || process.versions.icu !== '78.3' ||
    new Intl.Collator().resolvedOptions().locale !== 'en-US') {
  throw new Error('Pinned locale oracle requires Node 24.20.0, ICU 78.3, en-US');
}

const pairs = [
  ['a-1', 'a_1'], ['a1', 'a_1'], ['aA', 'aa'], ['a2', 'a10'],
  ['é', 'e'], ['e\u0301', 'é'], ['ß', 'ss'], ['中', 'あ'],
  ['😀', '\ue000'], ['a.', 'a-'], ['\ud800', '\ufffd'],
  ['\ud800', '\ud801'], ['\udc00', '\ufffd'], ['Å', 'A'],
  ['ñ', 'n'], ['Ω', 'O'], ['é', 'e\u0301'],
  ['\ud800é', '\ud800e\u0301'],
  ['x\ud800é', 'x\ud800e\u0301'],
  ['\udc00é', '\udc00e\u0301'],
  ['\udc00e\u0301', '\udc00é'],
  ['\ud800a', '\ud800\u00ada'],
  ['\ud800a', '\ud800\u200ba'],
  ['\ud800', '\ufffd'],
  ['\ufffd', '\ud800'],
  ['\udc00', '\ufffd'],
  ['\ud800A', '\ud800a'],
  ['\ud800a', '\ufffdz'],
];
const output = {
  node: process.versions.node,
  icu: process.versions.icu,
  locale: new Intl.Collator().resolvedOptions().locale,
  cases: pairs.map(([left, right]) => ({left, right, sign: Math.sign(left.localeCompare(right))})),
};
writeFileSync(new URL('./locale-vectors.json', import.meta.url), `${JSON.stringify(output, null, 2)}\n`);
