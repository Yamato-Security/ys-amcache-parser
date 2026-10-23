# ys-amcache-parser

Read a Windows **`Amcache.hve`** — inventoried executables (path, **SHA-1**, publisher) and PnP
devices — on any OS.

`amcache-core` is the reader (`parse_bytes(&[u8]) -> Amcache`, modern Windows 10/11 and legacy
`Root\File`); `amcache-forensic` adds graded findings (carrying SHA-1 when available) and the
**`amcache4n6`** CLI.

```console
$ git clone https://github.com/Yamato-Security/ys-amcache-parser.git
$ cd ys-amcache-parser
$ cargo build --release
$ ./target/release/amcache4n6 /path/to/Amcache.hve
```

Export every supported file and device field as JSON or as separate CSV tables:

```console
$ ./target/release/amcache4n6 --all --format json --output amcache.json /path/to/Amcache.hve
$ ./target/release/amcache4n6 --all --format csv --output amcache-csv /path/to/Amcache.hve
```

The summary and findings are always emitted. The `--files`, `--devices`, and `--all` selectors add
detailed records in every format. The supported formats are `text`, `json`, `jsonl`, and `csv`.
JSON Lines can be streamed directly to `jq`; CSV uses an output directory so file, device, finding,
and summary records keep distinct, stable columns. See [Output formats and schema](output.md).

See the [project README](https://github.com/Yamato-Security/ys-amcache-parser) for full usage and the
findings table, and [Validation](validation.md) for how correctness is established.

This is a modified fork of
[`SecurityRonin/amcache-forensic`](https://github.com/SecurityRonin/amcache-forensic). The upstream
history, attribution, and Apache-2.0 license are retained.

!!! caution "Interpret Amcache evidence carefully"

    Amcache records support file-presence and inventory conclusions; they are not, by themselves,
    proof that a program executed. The Publisher field is recorded PE metadata and is not proof of
    a valid Authenticode signature. Corroborate important conclusions with other artifacts and, when
    available, inspect the original executable.
