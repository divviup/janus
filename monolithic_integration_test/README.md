# Integration Test Notes

## Daphne

The [Daphne](https://github.com/cloudflare/daphne) testing functionality is implemented by running a
WASM-compiled version of Daphne inside [miniflare](https://miniflare.dev), inside a container. The
compiled artifacts are included in `artifacts/daphne_compiled`; the test container is built by the
build script & included in necessary test binaries which know how to load the image into Docker
themselves.

The compiled Daphne is from commit [`6301e712df216a0301c42cb3177110dd8217fa84`](
https://github.com/cloudflare/daphne/commit/6301e712df216a0301c42cb3177110dd8217fa84).

### Running Daphne integration tests

First, make sure your workstation is set up per the instructions in the repository root's README.md.

Once `docker` is installed, simply run `cargo test` to run the Daphne integration tests.

### Updating the version of Daphne under test

Compiling a new version of Daphne requires having [workers-rs](
https://github.com/cloudflare/workers-rs) and [wrangler](https://github.com/cloudflare/wrangler)
installed. (At time of writing, workers-rs contains a bug that must be worked around by installing
from a fix branch, via a command like:
`cargo install -q --git https://github.com/cloudflare/workers-rs --branch zeb/esbuild`. Follow
[workers-rs #204](https://github.com/cloudflare/workers-rs/issues/204) for more information.)

To update the version of Daphne in use:

1. Check out the [Daphne repository](https://github.com/cloudflare/daphne), and switch into the
   repository's `daphne_worker_test` directory.
1. Run `worker-build`; this will compile Daphne to WASM & place the results into the `build`
   directory.
1. Replace the content of `monolithic_integration_test/artifacts/daphne_compiled` in the Janus
   repository with the content of `daphne_worker_test/build/worker` from the Daphne repository.
1. Update this README to note the Daphne commit used to generate these artifacts!

### License

The contents of `artifacts/daphne_compiled` are a compiled artifact of the
[Daphne](https://github.com/cloudflare/daphne) project, which is licensed under the [BSD 3-Clause
License](https://github.com/cloudflare/daphne/blob/6301e712df216a0301c42cb3177110dd8217fa84/LICENSE),
reproduced below:

```
BSD 3-Clause License

Copyright (c) 2022, Cloudflare Inc.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```