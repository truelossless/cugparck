# Cugparck

Cugparck is a modern rainbow table library & CLI.

> A rainbow table is a precomputed table for caching the output of cryptographic hash functions, usually for cracking password hashes. Tables are usually used in recovering a key derivation function (or credit card numbers, etc.) up to a certain length consisting of a limited set of characters. It is a practical example of a space–time tradeoff, using less computer processing time and more storage than a brute-force attack which calculates a hash on every attempt, but more processing time and less storage than a simple key derivation function with one entry per hash [1].

![demo](https://imgur.com/4e8TeTx.png)

In particular, it implements the following features that may not be present in other rainbow table applications:

- Compressed delta encoding, a compression method described in [2]. based on delta encoding and rice compression and produces 10% to 15% smaller rainbow tables, compared to the classic prefix-suffix method.

- Maximality factor, a technique described in [3]. It starts from the observation that a greatly reduced number of starpoints can give a rainbow table roughly as good as a maximum rainbow table (which uses as many startpoints as there are possible passwords). This is because the last startpoints are very likely to cause a collision with an already existing chain.

- Filtration, a technique described in [3]. Sorting and deduplicating chains in the middle of the chain generation process allows to catch collisions earlier and avoids unecessary hasing.

## Features

- Rainbow table generation (also called offline phase)
    - GPU-accelerated rainbow table generation for CUDA-capable devices
    - Multithreaded CPU rainbow table generation for other devices
    - Compressed delta encoding
    - Maximality factor support
    - Filtration
    - Charset, maximum password length, chain length ... customization
    - Ability to generate multiple rainbow tables to bump the success rate
    - Close to the rainbow table theory [4, 5]. A single rainbow table has a success rate of 86.5%, while 4 tables are close to 99.96%.

- Attack using rainbow tables (also called online phase)
    - Fast table loading using full zero-copy deserialization and memory-mapped buffers
    - Multithreaded CPU attack
    - NTLM, MD4, MD5, SHA-1, SHA-2, SHA-3 support

## Installation

No executable is currently provided but I will work on getting a CI pipeline running for at least the Linux and Windows builds.

Compiling from source the CLI or library can be tough because a valid CUDA installation is required.

On Windows if you're kind enough to the NVIDIA and LLVM gods no further steps are needed and a `cargo build --release` should do the trick.

On Linux your best bet is using Docker to avoid incompabilities between CUDA/GCC/LLVM toolchains. [Follow the instructions here to get started](https://github.com/Rust-GPU/Rust-CUDA/blob/master/guide/src/guide/getting_started.md#docker).

Note that a specific nightly Rust toolchain is required. It will be downloaded automatically thanks to the `rust-toolchain` file.

## Contributing

This project is available under the MIT licence. Pull requests are more than welcome :)
If you want this to go further, don't hesitate to give me access to your cluster of 93845 GPUs with 10987345To of RAM!

I'm currently developing this on a GTX 1060 with 16Go of RAM, so I can't really test Cugparck with values close to u64::MAX.
I have done my best to avoid overflows (floats are used in formulas that may exceed u64::MAX, wrapping operations are used when needed etc.) but incorrect behaviors are very likely to happen as I can't test correctly big search spaces. So any help on testing Cugparck with big search spaces is appreciated.

Besides that, here is a list of things that could be improved/implemented/tested:
- AMD support (OpenCL? wgpu?)
- Using the CPU cores during the GPU calculations
- Better error checks and messages
- Better memory management, such as more precise memory predictions for the device's memory and host's RAM. This would allow to schedule better batches on the GPU, and make sure that no memory allocation fails.
- Support for external memory (SSD and/or HDD). I think [6] should be a great startpoint (pun intended).
- Support for distribution. Maybe MPI can be used? [3] Section 4 gives pointers to implement a distributed architecture with filtration.
- Using a `HashSet` instead of a sorted array (This would use more RAM but put less strain on the CPU).
- Smaller RAM footprint
- Implement checkpoints to speed up the attack phase as described in [7]

## Acknowledgments

This work is a continuation of a school project which studies the feasability of rainbow tables generation using the GPU.

I made a first single-threaded CPU implementation in C at https://github.com/gpucrack/NaiveRainbow.

My group continued the GPU implementation at https://github.com/gpucrack/GPUCrack but unfortunately I couldn't finish the project with them as I was abroad. This is why I decided to start Cugparck as a personal project, to further explore rainbow tables for fun.

This project wouldn't have been remotely possible without the help and explanations of our teachers, so all the credit goes to them!

In the interest of not associating this side project with anyone or accidently doxxing anyone, I am not mentioning directly any name. If you recognize yourself and want to be associated with this project, I'll be more than happy to include you in this section!

I would also like to thank all the contributors who helped create the excellent libraries used throughout this project. To name a few:
- [The Rust CUDA Project](https://github.com/Rust-GPU/Rust-CUDA)
- [rkyv](https://rkyv.org/)
- [Rayon](https://github.com/rayon-rs/rayon)
- [bitvec](https://github.com/bitvecto-rs/bitvec)

## Bibliography

[1] Wikipedia contributors. (2022, July 2). Rainbow table. In Wikipedia, The Free Encyclopedia. Retrieved 08:46, July 14, 2022, from https://en.wikipedia.org/w/index.php?title=Rainbow_table&oldid=1096095323

[2] Avoine, Gildas & Carpent, Xavier. (2013). Optimal Storage for Rainbow Tables. 10.1007/978-3-319-12160-4_9.

[3] Avoine, G., Carpent, X., & Leblanc-Albarel, D. (2021, October). Precomputation for Rainbow Tables has Never Been so Fast. In European Symposium on Research in Computer Security (pp. 215-234). Springer, Cham.

[4] Hellman, M. (1980). A cryptanalytic time-memory trade-off. IEEE transactions on Information Theory, 26(4), 401-406.

[5] Oechslin, P. (2003, August). Making a faster cryptanalytic time-memory trade-off. In Annual International Cryptology Conference (pp. 617-630). Springer, Berlin, Heidelberg.

[6] Avoine, G., Carpent, X., Kordy, B., & Tardif, F. (2017, July). How to handle rainbow tables with external memory. In Australasian Conference on Information Security and Privacy (pp. 306-323). Springer, Cham.

[7] Avoine, G., Junod, P., & Oechslin, P. (2005, December). Time-memory trade-offs: False alarm detection using checkpoints. In International Conference on Cryptology in India (pp. 183-196). Springer, Berlin, Heidelberg.