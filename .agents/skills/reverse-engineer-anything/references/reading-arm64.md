# Reading ARM64 code

How to read AArch64 (Armv8-A) code in Ghidra, as opposed to which REA tool to call.
Distilled from Austin Kim, _Reverse Engineering Armv8-A Systems_ (Packt, 2025),
cited as (AK ch. N). Lines marked _(not from the book)_ come from other experience;
weigh them accordingly.

## Registers and the AAPCS

- **Arguments go in x0 to x7** (AK ch. 1). Reading a call site starts with those
  registers before the `bl`; arguments beyond the eighth go on the stack
  _(not from the book)_.
- **The return value comes back in x0** (AK ch. 1). Check x0 immediately after a
  call; that is where `cbz`/`cbnz` tests usually look (AK ch. 5).
- **`w0` is the low 32 bits of `x0`.** `wn` names the low half of `xn` for any n
  (AK ch. 1). Writing `w0` also zeroes the upper 32 bits of `x0`, so `mov w0, #1`
  leaves `x0 == 1` _(not from the book)_.
- **x30 is the link register.** It holds the return address. Analysts read x30 to
  name the caller (AK ch. 1), and callees spill it to the stack (AK ch. 1).
- **x29 is the frame pointer** (AK ch. 11). The typical prologue pins it with
  `mov x29, sp` (AK ch. 1, 10). Saved x29 values on the stack form the frame
  chain that debuggers walk to print a call stack _(not from the book)_.
- **x8 is overloaded.** In user code it carries the system call number before
  `svc` (AK ch. 1, 5); as the AAPCS64 indirect result register it passes the
  address for a large return value _(not from the book)_.
- **xzr/wzr is the zero register.** `str wzr, [sp, #44]` initialises a stack slot
  to zero (AK ch. 9). It reads as zero and writes are discarded _(not from the
  book)_, so an `orr w0, wzr, ...` is a move.
- **Callee-saved registers.** A function that uses x19 and up saves and restores
  them beside x30 in its prologue and epilogue (AK ch. 1). The full AAPCS64
  caller/callee split is _(not from the book)_.
- **PC is not a general register.** Arithmetic cannot write it; only branches,
  exceptions and `ret` move it (AK ch. 1). There is no x86-style `lea` on it;
  code reaches data through `adrp` (below).

## Function prologue and epilogue

- **Push pair, pre-indexed:** `stp x29, x30, [sp, #-16]!` stores the pair and
  decrements sp in the same instruction; the stack grows downwards (AK ch. 1).
- **Pin the frame:** `mov x29, sp` (AK ch. 1, 10). In kernel listings this often
  sits after a second `stp` of saved registers (AK ch. 10).
- **Spilled arguments and locals** live at positive offsets from sp: `str w0,
  [sp, #28]`, `ldr w1, [sp, #20]` (AK ch. 4, 9). Unoptimised code reloads a
  local from the stack before every use; that is not data flow to chase.
- **The folded variant** is `sub sp, sp, #32` then `stp x29, x30, [sp, #16]`,
  with `add x29, sp, #16`; the callee's frame is built explicitly (AK ch. 4).
- **Pop pair, post-indexed:** `ldp x29, x30, [sp], #16` restores the registers
  and then adds 16 to sp (AK ch. 1, 5).
- **`ret` copies x30 to PC** (AK ch. 1). `ldp` of x29/x30 immediately before
  `ret` is the epilogue, whatever else the decompiler folds into it.

## Address formation: adrp plus add

- **`adrp` then `add` builds the address of a string or global.** The pair is
  `adrp x0, sym` followed by `add x0, x0, #:lo12:sym` (shown as `add x0, x0,
  #0x608` after `adrp x0, 188000` in AK ch. 1, and with the `:lo12:` syntax in
  AK ch. 4). Read the pair as one address computation.
- **The result usually becomes x0 for a call**, that is, the format string for
  `printf`/`puts` (AK ch. 9). Following the computed address into `.rodata`
  names the variable and gives the format string (AK ch. 2, 9).
- **A literal pool load is the same idea:** `ldr x0, ...` from a nearby literal
  also materialises an address _(not from the book)_.

## Calls, indirect calls and tail calls

- **`bl <target>`** branches and writes the return address to x30 in the same
  step (AK ch. 1, 5). A C function call compiles to `bl` (AK ch. 5).
- **`blr <Xt>`** is a call through a function pointer held in a register (AK ch. 5);
  callbacks and vtable dispatch compile the same way _(not from the book)_. Static analysis cannot always resolve the
  target; the book says this is where dynamic analysis is needed (AK ch. 10).
  Resolve what you can by finding where the register was loaded, typically
  `ldr x2, [x3, #8]` just before the `blr` (AK ch. 10).
- **`br <Xt>`** branches without setting x30 (AK ch. 5).
- **A trailing `b` instead of `ldp`/`ret` is a tail call.** A plain `b` does not
  update x30 (AK ch. 5), so the callee returns straight to the original caller
  _(tail-call reading of that fact, not stated as such in the book)_.
- **Library calls go through the PLT:** `bl 6c0 <puts@plt>` (AK ch. 2, 9). The
  PLT stub and GOT implement lazy binding (AK ch. 2); the `@plt` target is not
  the code that will run on first call.

## Conditional flow

- **`cmp`, `cmn` and `tst` only update the NZCV flags** and leave no result in a
  register (AK ch. 5). `cmp` is a subtraction whose result is thrown away
  (AK ch. 5); `tst` is a bitwise AND with the result discarded (AK ch. 5).
- **`b.eq`, `b.ne` and friends read those flags** through a condition code
  (AK ch. 5). Read the pair `cmp` plus conditional branch as one `if`.
- **Signed and unsigned conditions differ.** `ge`/`lt`/`gt`/`le` are signed
  (N versus V); `hs`/`lo`/`hi`/`ls` are unsigned (C and Z) (AK ch. 5). Picking
  the wrong family misreads the comparison, especially after `cmp w0, #0`.
- **The compiler inverts the branch, not the condition.** An `if (x > 0x100)`
  becomes `cmp` + `b.le` over the body (AK ch. 9); `if (x == 0)` becomes `b.ne`
  over it (AK ch. 9). The taken branch skips the `then` block.
- **`cbz`/`cbnz` and `tbz`/`tbnz` do not touch NZCV** (AK ch. 5). `cbz x0, L`
  is a null check on a return value (AK ch. 5); `tbz x1, #7, L` tests one bit of
  a status register, such as a DAIF mask bit read with `mrs` (AK ch. 5).
- **`cbnz` builds loops:** decrement a counter and branch back while it is
  non-zero (AK ch. 5).
- **`ccmp` chains comparisons** in kernel start-up checks (AK ch. 1). `csel`,
  `csinc` and `cset` select without branching _(not from the book)_: if the
  decompiler shows a value chosen by a condition but the listing has no branch,
  a select instruction is the reason.

## Load and store addressing

- **`ldr`/`str` basic forms** are `ldr x1, [x2]` (dereference) and `ldr x1,
  [x2, #0x10]` (base plus offset) (AK ch. 4).
- **The offset is a struct field offset.** `str w1, [x0, #28]` writes the field
  28 bytes into the structure; name fields from these offsets (AK ch. 4, 10).
  `pahole` confirms a layout when debug info exists (AK ch. 10).
- **Pre-indexed writeback:** `str x30, [sp, #-32]!` updates sp first, then
  stores (AK ch. 1). **Post-indexed:** `ldp x19, x30, [sp], #16` loads first,
  then updates sp (AK ch. 1). The `!` and the trailing immediate are what tell
  the two apart.
- **Access size is in the mnemonic.** `ldrb`/`ldrsh` and kin load 8 or 16 bits;
  unsigned forms zero-extend, signed forms sign-extend into the register
  (AK ch. 4). A `ldrsb` of a flag byte is a signed quantity.
- **Sp-relative access is stack traffic.** `str` to `[sp, #n]` is saving a value,
  `ldr` from it is reloading a local, not memory-mapped I/O (AK ch. 4).

## Kernel code: system registers and exception levels

- **System registers move only through `mrs` and `msr`** (AK ch. 1): `mrs x1,
  esr_el1`, `msr ttbr0_el1, x1` (AK ch. 1, 10). No `ldr` touches them.
- **The register name's suffix is the lowest exception level that can access it**
  (AK ch. 1, 10). `esr_el2` implies at least EL2 code; a kernel function reading
  `esr_el1` is ordinary EL1 code (AK ch. 10).
- **Exception levels are privilege levels:** EL0 user application, EL1 Linux or
  RTOS kernel, EL2 hypervisor, EL3 secure monitor (AK ch. 1). `svc`, `hvc` and
  `smc` step up from one level to the next (AK ch. 1, 5).
- **A system call is `mov x8, #N` then `svc #0x0`** (AK ch. 5, 8). The kernel
  dispatches on x8 (AK ch. 1, 8). System call numbers differ between 32-bit and
  64-bit Arm (AK ch. 8), so use the AArch64 table.
- **Exception cause lives in ESR_ELx bits 31 to 26.** The kernel extracts it
  with `lsr w2, w1, #26` after `mrs x1, esr_el1`, then switches on the value
  (AK ch. 3, 10).
- **Exception vectors are VBAR_ELx plus a fixed offset** (AK ch. 1); in the
  kernel the table is the `vectors` symbol, entries of which branch to handlers
  such as `el1t_64_sync` (AK ch. 10).
- **`mrs xN, sp_el0` is `current`.** The kernel keeps the current `task_struct`
  pointer in sp_el0 (AK ch. 10), so a load of `[x20, #24]` right after it is a
  field of `task_struct` (AK ch. 8, 10). `cpu_switch_to` writes sp_el0 on every
  context switch (AK ch. 10).

## ELF facts that matter for finding code

- **Identify before disassembling.** `file` and `readelf -h` report the class
  and `Machine: AArch64`; the same filename can hold a 32-bit Arm build
  (AK ch. 9). `e_machine` for AArch64 is EM_AARCH64 (AK ch. 2).
- **`e_type` tells you what you have:** ET_EXEC (directly runnable), ET_DYN
  (shared object or PIE executable), ET_REL (object file, including `*.ko`),
  ET_CORE (core dump) (AK ch. 2).
- **Code lives in `.text`;** `sh_addr` gives where it starts in memory and
  `sh_offset` where it sits in the file (AK ch. 2). SHF_EXECINSTR marks
  executable sections (AK ch. 2).
- **Strings live in `.rodata`,** initialised globals in `.data`, zero-initialised
  globals in `.bss` (AK ch. 2). An `adrp`/`add` pair resolving into `.rodata` is
  a string or constant.
- **`e_entry` is the first instruction** of an ET_EXEC program, or the
  initialiser of a library (AK ch. 2).
- **Imports come through the GOT and PLT** (AK ch. 2). An import proves the
  binary links the function, not that any path calls it.
- **Kernel artefacts:** `vmlinux` is a statically linked ELF with debug info;
  its `.head.text` holds start-up code, `.init.text` initialisation, `.exit.text`
  shutdown (AK ch. 10). A `*.ko` is ET_REL and its `.modinfo` section carries
  licence, author, `depends=` and `vermagic` (AK ch. 10).
- **Corrupted headers:** when `file` and `readelf` fail on the magic bytes,
  `xxd` still shows the raw stream (AK ch. 9).

## Compiler shape of the code you read

- **Optimisation level changes the listing** for the same source (AK ch. 6).
  Unoptimised code stores every local to the stack and reloads it (AK ch. 9).
- **`printf` can become `puts`** when the format string has no conversion
  specifier, ends in a newline and takes no extra arguments (AK ch. 9). A call
  to `puts@plt` with one `adrp`/`add` argument is that rewrite.
- **Log macros compile to the real message.** Source macros hide what is
  printed, but the binary shows the exact string and its call (AK ch. 9).
- **Loop internals encode `break`, `continue` and early `return`** as branches
  out of or around the loop body (AK ch. 9); a `b` to the shared `ldp`/`ret`
  block is an early return.

## Not covered

What an ARM64 reader needs but the book does not address. The book's dynamic
analysis chapters (GDB, crash dumps, uftrace; AK ch. 11 to 13) are left out here
because REA's static route is the reader's default.

- AAPCS64 detail beyond x0 to x7 and x0 returns: stack arguments, variadic
  calls, x8 indirect results, HFA and SIMD argument passing, and the exact
  caller-saved list.
- The select family (`csel`, `csinc`, `csneg`, `cset`) and `ccmp` semantics,
  beyond one `ccmp` in a listing (AK ch. 1).
- `adrp` immediate encoding and page arithmetic; only the idiom is shown.
- The AArch64 memory model: exclusive load/store (`ldxr`/`stxr`), atomics,
  barriers (`dmb`, `dsb`, `isb`).
- NEON and SVE registers, and how they pass arguments.
- How pointer authentication (`paciasp`, `autiasp`), BTI and MTE appear in
  decompiler output. The book explains the features themselves (AK ch. 15).
- Switch statements and jump tables on Arm64; the book's one `switch` shows only
  `cmp`/`b.eq` (AK ch. 3).
- AArch64 relocation types, `.eh_frame` and unwinding. The GOT and PLT lazy
  binding are covered (AK ch. 2).
- AArch32 interworking and Thumb.
- Ghidra-specific rendering of any of the above.
