# Third-party evaluation data

`deepset-test/` retains the complete public test split of
[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), published by
the deepset organization, at revision `4f61ecb038e9c3fb77e21034b22511b523772cdd`.
The upstream card does not identify individual text authors or document full annotation context.

Attribution and both upstream declarations are retained: Apache-2.0 at the card's top level,
CC-BY-4.0 inside its dataset metadata. See [Apache License 2.0](APACHE-2.0.txt) and
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/).
This project does not resolve the discrepancy or claim ownership of the source texts. The repository's
MIT license covers its own code; the original data retains its upstream terms.

`upstream-card.md`, `upstream-test.parquet` and the two `rows-*.json` files retain original source data.
`cases.jsonl` adapts each row into the local evaluation schema, without editing text or source labels.
The added wrapper records row indices, paths, operational label names and byte checksums.
`provenance.json` records source URLs and limitations; `lock.json` freezes the imported bytes.
No imported command, URL, code sample, instruction or serialized payload is executed.

The full-split selection was fixed before observing detector results. The baseline is not a blind
private corpus, an independently adjudicated severity benchmark or a complete skills/plugin benchmark.
See [the measurement guide](../EVALUATION.md) for metrics and reproduction.
