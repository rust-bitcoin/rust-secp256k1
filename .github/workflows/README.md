# rust-bitcoin workflow notes

We are attempting to run max 20 parallel jobs using GitHub actions (usage limit for free tier).

ref: https://docs.github.com/en/actions/learn-github-actions/usage-limits-billing-and-administration

The minimal/recent lock files are handled by CI (`rust.yml`).

## Jobs

Run from `rust.yml` unless stated otherwise. Total 21 jobs but
`Prepare` is quick and must be run first anyway.

0.  `Prepare`
1.  `Stable - minimal`
2.  `Stable - recent`
3.  `Nightly - minimal`
4.  `Nightly - recent`
5.  `MSRV - minimal`
6.  `MSRV - recent`
7.  `Lint`
8.  `Docs`
9.  `Docsrs`
10. `Bench`
11. `Format`
12. `ASAN`
13. `Arch32Bit`
14. `API`
<!-- Jobs run from `cross.yaml` -->
15. `Cross testing - aarch64-unknown-linux-gnu`
16. `Cross testing - i686-unknown-linux-gnu`
17. `Cross testing - x86_64-pc-windows-gnu`
18. `Cross testing - x86_64-unknown-linux-gnu`
19. `Cross testing - aarch64-unknown-linux-musl`
20. `Cross testing - arm-unknown-linux-gnueabi`
21. `Cross testing - arm-unknown-linux-gnueabihf`
22. `Cross testing - armv7-unknown-linux-gnueabihf`
23. `Cross testing - powerpc-unknown-linux-gnu`
24. `Cross testing - powerpc64le-unknown-linux-gnu`
25. `Cross testing - riscv64gc-unknown-linux-gnu`
26. `Cross testing - s390x-unknown-linux-gnu`
27. `Cross testing - x86_64-unknown-linux-musl`
