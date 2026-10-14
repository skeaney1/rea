# Reading native code

How to read what Ghidra returns, as opposed to which REA tool to call. Distilled
from Nance and Eagle, _The Ghidra Book_, 2nd ed. (No Starch, 2026), cited as
GB, and Dang et al., _Practical Reverse Engineering_ (Wiley, 2014), cited as PRE.
Lines marked _(not from the books)_ come from other experience; weigh them accordingly.

## Identify the toolchain before reading functions

The toolchain decides what the start-up code, strings and library noise look like.

- **Mangled names:**
  - `?name@Class@@...` is the Microsoft C++ scheme.
  - `_ZN...` is the Itanium scheme, used by g++ and clang (GB ch. 20).
  - `_ZN...17h<16 hex>E` is legacy Rust and `_R...` is Rust v0 _(not from the books)_.
- **RTTI:** MSVC RTTI is well understood, and Ghidra lists the classes it finds. In a stripped g++ binary, search the strings for class names such as `8SubClass` and follow the references back to the typeinfo and vtable (GB ch. 20).
- **REA's metadata tools come first:**
  - `inspect_rust_binary` and `inspect_go_binary` read the embedded metadata.
  - `inspect_pe_resources` reads version resources.
  - A missing record is unknown, not negative.

## Find the program's own entry, not the loader's

The entry point is compiler start-up code (GB ch. 20).

- **gcc on Linux:** `main` is the first argument to `__libc_start_main`, loaded into `RDI` just before the call.
- **MSVC:** `main` is the three-argument call that follows `__p___argv`, `__p___argc` and `_get_initial_narrow_environment`, closely followed by `_cexit` or `exit`.
- **Rust** _(not from the books)_: the C-level `main` calls `std::rt::lang_start` (often inlined into `lang_start_internal`), with the user's `main` function pointer as its first argument. Command-line parsing (for example clap) and dispatch to subcommands start there.

## Skip library code

Statically linked binaries mix library and application code. Do not reverse engineer `malloc` (GB ch. 13).

- Ghidra's Function ID analyser names functions that match its databases. Trust a match on a large function; distrust one on a tiny function, because short functions match by chance.
- Rust, Go and C++ binaries carry thousands of standard-library and crate functions. Start from the application's own anchors and work outwards:
  - unique strings;
  - error messages;
  - imports used only at a few call sites;
  - the user `main`.

  Do not walk the function list in address order.

## Read decompiler output critically

The decompiler and the listing are produced independently and can disagree. When they do, the assembly is the ground truth (GB ch. 19).

- **Variadic calls (`printf` and its kin):** the decompiler guesses how many arguments are passed. A wrong guess can hide statements whose results it thinks unused. If arguments look missing, read the call site's assembly.
- **Casts everywhere** (`(ulong)`, `undefined4 *`) mean missing type information, not program behaviour.
- **`/* WARNING: Removing unreachable block */`** means code was dropped as dead. Opaque predicates exploit this, so check the dropped block before concluding a branch never runs (GB ch. 19, 21).
- **`halt_baddata()` or "Bad instruction" right after a call** usually means the callee does not return (exit, abort, a panic) and Ghidra did not know. The code after it is not real flow.
- **Pointer-plus-offset accesses on one parameter** (`*param_1`, `param_1[1]`, `*(char *)(param_1 + 1)`) indicate a structure. Name the fields from the offsets. Note that padding exists (GB ch. 19).
- **Format strings** are the cheapest source of variable names and types (GB ch. 19).
- **When a reconstruction depends on a recovered layout, pin it.** Put compile-time size and offset assertions in the rebuilt code, such as Rust `const _: () = assert!(size_of::<T>() == 0x18);` and `offset_of!`, so that a wrong guess fails the build instead of corrupting data _(not from the books)_.

## Recognise compiled control flow

- **Switch statements** compile to a jump table for dense case values, or to a binary search for sparse ones.
  - The decompiler shows a binary search as nested `if`s comparing against medians, with cases reordered from the source.
  - A mix is possible: a table for one range, a search for the rest (GB ch. 20).
- **Inlining:** optimised builds inline small functions and fold constants. A missing call does not mean a missing function. A constant pushed as an argument can be another function's whole body (GB ch. 20).
- **Debug and release builds differ a lot.** MSVC debug builds add runtime checks (`/RTC`). Do not mistake check code for application logic (GB ch. 20).

## x64 calling conventions

From PRE ch. 1:

- **Windows x64 has one convention.** The first four integer or pointer arguments go in `RCX`, `RDX`, `R8` and `R9`, and the rest on the stack. The caller also reserves 32 bytes of shadow space.
- **System V** (Linux and macOS) uses `RDI`, `RSI`, `RDX`, `RCX`, `R8` and `R9`.
- **`RBP` is usually a general-purpose register on x64.** Locals are addressed from `RSP`.
- **Writing a 32-bit register clears the upper 32 bits**, so `xor eax, eax` zeroes `RAX`.
- **RIP-relative addressing** (`[rip + x]`) is how x64 code reaches globals and strings. Follow it to the data.

**A flag or option argument is a constant at the call site.** To learn the flags passed to a Windows API, read the register that carries that parameter just before the call, and decode the value against the API's documented constants. Name both the constant and its decoding.

## What imports and strings prove

From GB ch. 21:

- **An import proves the binary links a function. It does not prove the function is called on a given path.** Trace the reference to its call sites and to the subcommand or feature that reaches them.
- **Absent imports do not prove absent behaviour.** `GetProcAddress` and `LoadLibrary`, API hashing and indirect calls through tables all hide what is called. Resolve an indirect call by tracing how its target register was filled.
- **String search misses some strings:**
  - strings that are not NUL-terminated (Rust `&str` and Go strings are pointer plus length) _(not from the books)_;
  - strings built at run time;
  - encoded strings.

  So the absence of a string is weak evidence. When a decode loop exists, recover the plaintext by replicating it, rather than guessing.

- **Signs of a packed binary:** few imports, high-entropy sections and a small amount of code. The stub is not the program, and analysis of it says nothing about the payload.

## State what you did not check

- Record the search boundary of every negative claim. For example, "no call site found among the references to `X`" is a negative claim; say how far the search went.
- If REA or Ghidra did not reach a function (a decompile timed out, or a reference was unresolved), the finding is INCONCLUSIVE, not REFUTED.
