# amcache-forensic

Read a Windows **`Amcache.hve`** — inventoried executables (path, **SHA-1**, publisher) and PnP
devices — on any OS.

`amcache-core` is the reader (`parse_bytes(&[u8]) -> Amcache`, modern Windows 10/11 and legacy
`Root\File`); `amcache-forensic` adds graded findings (each carrying the SHA-1) and the
**`amcache4n6`** CLI.

```console
$ cargo install amcache-forensic
$ amcache4n6 /path/to/Amcache.hve
```

See the [project README](https://github.com/SecurityRonin/amcache-forensic) for full usage and the
findings table, and [Validation](validation.md) for how correctness is established.
