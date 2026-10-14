# Diffing, auditing and unpacking binaries

Method for comparing builds, auditing for memory-safety bugs and handling packed
samples. Distilled from Álvarez Pérez and Tiwari, _Ghidra Software
Reverse-Engineering for Beginners_, 2nd ed. (Packt, 2025), cited as GB4B. Use
REA's `compare_functions`, `compare_artifacts` and `find_changed_behavior` for
the comparisons. Lines marked _(not from the book)_ come from other experience.

## Comparing builds

Start with function identity, then inspect changed behaviour.

- Use similarity first to align functions between builds. BSim-style comparison uses decompiler-derived feature vectors over data flow and control flow, then scores possible matches by cosine similarity. (GB4B ch. 8)
- Treat a high similarity score as a candidate match, not proof of identical behaviour. Similarity says how much of the feature set overlaps, while confidence estimates how likely the pair is a causal match. (GB4B ch. 8)
- If one build has symbols and the other is stripped, use the symbolled build as the map. Match known functions, then follow references and caller chains in the stripped build to recover user code such as `main`. (GB4B ch. 8)
- For a pair of matched functions, look for the differences between code blocks of the same function (GB4B ch. 8). Then ask whether each difference changes data flow, control flow, call targets, constants used in checks, or copied sizes _(not from the book)_.
- Expect harmless differences between two builds of the same program. The book's stripped and unstripped example had small structural differences but no major functional change. (GB4B ch. 8)
- Patch diffing compares a vulnerable version with a patched version to identify the exact fix (GB4B ch. 8). Do not call a difference a patch until you can explain the old and the new behaviour _(not from the book)_.
- A classic security patch pattern is an unchecked copy becoming a bounded copy plus explicit NUL termination, for example `strcpy` replaced by `strncpy` with `sizeof(buffer) - 1`. (GB4B ch. 8)
- Confirm a patch by tracing the relevant input to the old sink and the new guard. A safer function name is not proof; the new bound must actually stop the overflow _(not from the book)_.
- When compiler output differs from source expectations, account for optimisation before judging the change. The book's stack buffer example grew from a source size of 200 bytes to a 212-byte binary layout because of stack alignment. (GB4B ch. 9)
- Remember that compiler optimisation can also alter security-relevant behaviour, such as removing a `memset` whose target is not used afterwards. (GB4B ch. 9)
- For vulnerability research, diffing is useful because real-world fixes may be hard to spot without comparing the old and new binaries. (GB4B ch. 8)

## Auditing for memory-safety bugs

Find dangerous operations, then prove the path and the missing check. This covers stack overflows, heap overflows and format strings only; the book leaves out use-after-free, double free, integer overflow and off-by-one bugs (GB4B ch. 9).

- Focus first on C and C++ style memory corruption, where direct memory access makes stack, heap and format string errors common. (GB4B ch. 9)
- Start from unsafe functions, but do not stop there. Finding the function only gives a candidate; confirmation requires checking the arguments and previous checks in each caller. (GB4B ch. 9)
- For stack overflows, look for copies into local stack buffers where the copied length can exceed the space reserved in the function frame. (GB4B ch. 9)
- Prioritise calls such as `strcpy`, `strcat`, `strncat`, `gets` and `memcpy` as stack-overflow candidates. (GB4B ch. 9)
- Confirm a stack-overflow candidate by deriving the destination size from the binary layout, then comparing it with the maximum bytes the source can supply and any length check before the call. (GB4B ch. 9)
- Do not assume the source-level size is the binary size. Use the stack offsets Ghidra recovered, because alignment and optimisation can change the apparent local layout. (GB4B ch. 9)
- For heap overflows, look for heap allocation followed by a write or copy into that allocation. (GB4B ch. 9)
- Prioritise `malloc`, `calloc`, `resize` and `free` when finding heap-managed buffers, then inspect later writes such as `strcpy` into the returned pointer. (GB4B ch. 9)
- Confirm a heap-overflow candidate by reading the allocation size passed to the allocator and checking whether later writes are bounded to that size. (GB4B ch. 9)
- For format string bugs, look for a formatting function whose format parameter comes from external input instead of a fixed format string. (GB4B ch. 9)
- Prioritise `printf`, `fprintf`, `sprintf`, `snprintf`, `vsprintf`, `vprintf`, `vsnprintf` and `vfprintf` as format-string candidates. (GB4B ch. 9)
- Confirm a format-string candidate by tracing the format argument. A user-controlled format can crash the program or leak stack and address data, which can help bypass ASLR. (GB4B ch. 9)
- For `sscanf`, check the return value before trusting output variables. The return value is the number of successfully scanned values, and variables not scanned may contain unpredictable data. (GB4B ch. 10)
- A vulnerable `sscanf` pattern is using parsed variables when the return value is absent, unchecked, or compared against a value lower than the number of output variables. (GB4B ch. 10)
- Automate only generic patterns. The book says logical and architectural bugs are not generally automatable, while memory corruption patterns can often be scripted. (GB4B ch. 10)
- When scripting an audit, enumerate symbols for the target unsafe function, enumerate references, recover the containing caller, then decompile the caller before analysing it. (GB4B ch. 10)
- Use P-Code for scripted checks when the pattern is data-flow based. P-Code abstracts over processor instructions and lets one script handle multiple architectures that Ghidra translates to P-Code. (GB4B ch. 10)
- In P-Code, inspect `CALL` operations to the unsafe function, then examine operands, outputs and descendants to see whether return values or derived variables are checked correctly. (GB4B ch. 10)
- Keep assembly in the loop for human review. The book says P-Code is better for scripting, while assembly is easier for humans to read. (GB4B ch. 10)
- Dynamic confirmation is valid evidence. Fuzzing sends inputs and watches for crashes; after a crash, use the debugger and Ghidra's recovered code and names to understand the failing path. (GB4B ch. 9)
- If exploitability matters, prove control, not just crash. In the stack-overflow example, the book confirms overwrite of saved frame data and the instruction pointer before moving to shellcode. (GB4B ch. 9)

## Recognising and handling packing

Static analysis can find the wrapper. The payload may only appear after execution or de-obfuscation. The debugger steps below run the sample: in REA they need an explicit runtime request and an isolated VM, as the skill's runtime rules require. Without both, report the payload as not recovered.

- Treat packing as an obfuscation layer intended to make analysis harder and to evade signature-based detection. (GB4B ch. 17)
- A new file hash does not necessarily mean new functionality. Malware families often produce many packed or obfuscated variants with different hashes. (GB4B ch. 17)
- If strings show mostly ordinary section names, runtime APIs and library names, and no clear URL or malicious indicator, static analysis may only be seeing the wrapper. (GB4B ch. 17)
- Imports such as `VirtualAlloc` and `VirtualProtect` are strong unpacking leads. Malware commonly allocates memory, writes de-obfuscated bytes there, changes protection to executable if needed, then transfers control. (GB4B ch. 17)
- Also watch for `GetModuleHandleA`, `GetProcAddress`, dynamic library loading, and hash-based API resolution. These hide capabilities that would otherwise appear as static imports or API-name strings. (GB4B ch. 17)
- Static analysis of a packed sample can still identify the compiler, the start-up path and the allocation and protection imports (GB4B ch. 17). The book finds the de-obfuscation loop and the transfer into unpacked code by debugging, with a hardware breakpoint on the newly allocated memory, not statically (GB4B ch. 17).
- Static analysis of a packed sample may not reveal the true C2 URL or payload strings. In the book's Cobalt Strike sample, the C2 URL was not visible statically because it was inside packed shellcode. (GB4B ch. 17)
- Before dynamic work, use an isolated Windows VM. The book warns against malware escaping through shared host resources, shared Clipboard, shared storage or reachable administrative shares. (GB4B ch. 17)
- Prefer local debugging in the isolated VM when that reduces host exposure. Remote debugging requires network connectivity between guest and host, which adds risk. (GB4B ch. 17)
- Do not break on allocation APIs too early. Loader activity can hit `VirtualAlloc` before the program reaches its own code, so first reach the program entry or `main` where possible. (GB4B ch. 17)
- For known compiler start-up code, find `main` by locating exit routines such as `_exit`, `_cexit` or `ExitProcess`; the CRT start-up function usually calls `main` just before the exit routine. (GB4B ch. 17)
- The generic unpacking loop is: break on allocation, step out to get the returned base address, set a read or write hardware breakpoint on that new memory, then resume until the writer reveals the de-obfuscation code. (GB4B ch. 17)
- After the decryption or copy loop, break on the indirect transfer into the new region, such as an indirect jump or call, or on the thread start routine that performs it. (GB4B ch. 17)
- When the full region is de-obfuscated, dump it and analyse the dumped bytes as a new artefact with the correct processor, bitness, endianness and compiler assumptions. (GB4B ch. 17)
- Account for variants. Some malware copies encrypted bytes first and decrypts in place later, and some uses `Nt` or `Zw` allocation APIs instead of `VirtualAlloc`. (GB4B ch. 17)
- Once inside the unpacked code, strings and network indicators may become visible. In the book's sample, the unpacked shellcode exposed a `User-Agent` and C2 IP address. (GB4B ch. 17)
- Confirm an indicator by watching it used, not just present. The book sets read breakpoints on the recovered strings and checks the call stack when execution enters `wininet.dll`. (GB4B ch. 17)
- Improve decompiler output on dumped payloads by applying known structures and constants, for example PE header types and optional-header magic values, before reasoning about API resolution logic. (GB4B ch. 17)
