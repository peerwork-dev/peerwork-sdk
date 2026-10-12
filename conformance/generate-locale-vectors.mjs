// Direct Node 24 / ICU baseline for the historical composeProtocol
// localeCompare comparator. These strings never leave this conformance input.
import {writeFileSync} from 'node:fs';

const pairs = [
  ['a-1', 'a_1'], ['a1', 'a_1'], ['aA', 'aa'], ['a2', 'a10'],
  ['é', 'e'], ['e\u0301', 'é'], ['ß', 'ss'], ['中', 'あ'],
  ['😀', '\ue000'], ['a.', 'a-'], ['\ud800', '\ufffd'],
  ['\ud800', '\ud801'], ['\udc00', '\ufffd'], ['Å', 'A'],
  ['ñ', 'n'], ['Ω', 'O'], ['é', 'e\u0301'],
];
const output = {
  node: process.versions.node,
  icu: process.versions.icu,
  locale: new Intl.Collator().resolvedOptions().locale,
  cases: pairs.map(([left, right]) => ({left, right, sign: Math.sign(left.localeCompare(right))})),
};
writeFileSync(new URL('./locale-vectors.json', import.meta.url), `${JSON.stringify(output, null, 2)}\n`);
