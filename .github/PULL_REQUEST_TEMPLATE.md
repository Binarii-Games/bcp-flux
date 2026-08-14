## Summary

What this change does, and why.

## Details

Anything a reviewer needs to follow the change: the design, the trade-offs, and
the edge cases you considered. For concurrency changes, bring the reasoning with
the patch (which loads and stores are relaxed against acquire/release, what a
racing reader can and cannot observe, and worked interleavings).

## Checklist

- [ ] Signed off with the Developer Certificate of Origin (`git commit -s`).
- [ ] Builds and tests on Windows, Linux, and macOS from the same `CMakeLists.txt`.
- [ ] Fast suite passes: `ctest --test-dir build -LE bench --output-on-failure`.
- [ ] Tests run clean under sanitizers (ASan and UBSan, and TSan for anything
      touching the lock-free code).
- [ ] Documentation updated if behaviour, the public API, or the wire format changed.
