# AGENTS.md — C++ → Production-Standard Rust 2024

## Mission

Systematically convert this repository from C++ to **production-quality Rust 2024** while preserving externally observable behavior and eliminating the need for `unsafe` Rust.

The finished Rust implementation must be:

- Rust 2024 edition.
- Safe Rust only: **no `unsafe` blocks, `unsafe fn`, `unsafe impl`, `unsafe trait`, or `unsafe` attributes**.
- Production-ready: correct, tested, observable, maintainable, performant enough for the workload, and operationally documented.
- Behavior-compatible with the C++ implementation unless an intentional incompatibility is explicitly documented and approved.
- Free of C/C++ FFI in the production Rust path unless a separate, explicitly approved migration boundary exists. Prefer replacing native dependencies with safe Rust equivalents.

Do not treat "it compiles" as completion.

---

## Non-Negotiable Rules

1. **Never add `unsafe` Rust.**
   - Do not use `unsafe` as a shortcut around ownership, lifetimes, aliasing, FFI, layout, concurrency, initialization, or performance problems.
   - If a dependency requires `unsafe` internally, that does not automatically violate this repository rule; evaluate whether its public API provides a safe abstraction and whether the dependency is acceptable under the project's supply-chain policy.
   - Do not hide unsafety behind macros, generated code, build scripts, or dependencies merely to evade review.

2. **Preserve semantics before redesigning.**
   - First reproduce the C++ behavior.
   - Then improve architecture, APIs, or algorithms in separately reviewable changes.
   - Document deliberate behavior changes.

3. **Migrate incrementally.**
   - Keep the repository buildable and testable at every meaningful checkpoint.
   - Prefer small vertical slices over a large mechanical rewrite.
   - Each migrated component must have a clear owner, test strategy, and rollback/containment strategy.

4. **Do not silence correctness signals.**
   - Do not weaken lints, delete failing tests, broadly suppress warnings, or relax CI gates to make migration pass.
   - Every exception must be narrowly scoped, justified, and tracked.

5. **Measure production behavior.**
   - Validate correctness, latency, throughput, memory use, startup behavior, resource consumption, and failure behavior where relevant.
   - Performance claims must be supported by representative benchmarks or profiling.

---

## Migration Workflow

For every component, follow this order unless there is a documented reason not to.

### 1. Inventory

Before changing code, identify:

- Public APIs and externally observable behavior.
- Callers and dependencies.
- Threading and synchronization assumptions.
- Ownership and lifetime rules.
- Error and exception behavior.
- Input validation and boundary conditions.
- Serialization, wire, file, and ABI formats.
- Resource ownership: files, sockets, locks, processes, memory, handles, etc.
- Platform-specific behavior.
- Build flags and generated code.
- Existing tests, benchmarks, fuzz targets, and production diagnostics.
- Security-sensitive operations.
- C++ undefined-behavior hazards.

Record important findings in migration notes or issue tracking rather than relying on tribal knowledge.

### 2. Characterize the C++ behavior

Before translating implementation details, establish a behavioral specification from:

1. Existing tests.
2. Public documentation/contracts.
3. Call sites.
4. Runtime observations.
5. Focused characterization tests added during migration.

Pay special attention to behavior that C++ permits accidentally but callers may rely on.

### 3. Design the safe Rust boundary

Map C++ concepts to idiomatic safe Rust:

| C++ concept | Preferred Rust model |
|---|---|
| Owning pointer | `Box<T>`, `Vec<T>`, `String`, or an owning domain type |
| Shared ownership | `Arc<T>` only when ownership is genuinely shared |
| Unique ownership | Direct ownership / `Box<T>` |
| Borrowed pointer/reference | `&T` / `&mut T` |
| Nullable pointer | `Option<&T>`, `Option<Box<T>>`, or an explicit handle type |
| Raw buffer + length | `&[T]` / `&mut [T]` |
| C string | `&CStr` / `CString` only at a necessary boundary |
| Variant/tagged union | `enum` |
| Error code | `Result<T, E>` |
| Optional value | `Option<T>` |
| Exception | `Result` / explicit domain error |
| RAII cleanup | `Drop` and scoped ownership |
| Mutex | `Mutex<T>` / `RwLock<T>` |
| Atomic state | `Atomic*` types with explicitly reasoned ordering |
| Thread-local state | Safe Rust thread-local facilities |
| Callback | Closure / trait object / generic callback |
| Template policy | Trait + generic type |
| Virtual interface | Trait |
| Macro metaprogramming | Prefer traits/generics/procedural macros where justified |
| Manual allocation | Standard collections or safe allocator-aware abstractions |
| `memcpy`-style copying | Safe slice/collection operations |
| Manual object lifetime | Normal Rust ownership and initialization |
| C++ union/type punning | Explicit enum/representation or safe conversion |
| Integer sentinel | `Option`, enum, or dedicated newtype |
| Global mutable state | Avoid; otherwise safe synchronization such as `OnceLock`/`Mutex` |

Do not mechanically translate syntax. Translate **ownership, invariants, state transitions, and contracts**.

### 4. Implement the smallest vertical slice

A slice should ideally include:

- Rust implementation.
- Unit tests.
- Integration/characterization tests where applicable.
- Error handling.
- Logging/metrics/tracing needed for production diagnosis.
- Documentation for non-obvious invariants.
- Benchmark coverage if performance-sensitive.

### 5. Differential validation

Where practical, run equivalent inputs through C++ and Rust and compare:

- Return values.
- Serialized/wire output.
- State transitions.
- Errors and error categories.
- Ordering guarantees.
- Boundary behavior.
- Resource behavior.
- Performance characteristics.

For nondeterministic systems, compare defined invariants rather than incidental ordering.

### 6. Remove the old implementation

Only remove C++ code after:

- Rust behavior is sufficiently characterized.
- Required tests pass.
- Production-relevant observability exists.
- Performance is acceptable.
- No remaining callers depend on the old path.
- Build/package/release tooling no longer requires it.
- Migration tracking is updated.

Avoid leaving dead C++ and Rust implementations indefinitely.

---

## Rust 2024 Standards

Use the Rust 2024 edition and current stable Rust unless the repository explicitly pins another supported toolchain.

Recommended baseline:

- `cargo fmt --check`
- `cargo check --all-targets --all-features`
- `cargo test --all-targets --all-features`
- `cargo clippy --all-targets --all-features -- -D warnings`
- Release-mode tests/benchmarks where relevant.
- `cargo doc --no-deps` for library/public API changes.

Configure the workspace so accidental unsafe code fails CI. Prefer a crate/workspace policy equivalent to:

```rust
#![deny(unsafe_code)]
```

and enforce it consistently across production crates.

Do not use `#[allow(unsafe_code)]` as a migration escape hatch.

Use strong typing to make invalid states difficult or impossible to represent.

Prefer:

- `Result` instead of panics for expected operational failures.
- `Option` instead of sentinel values.
- Newtypes for units, IDs, handles, and security-sensitive values.
- Exhaustive enums for finite states.
- Borrowing rather than cloning when ownership does not require a clone.
- Explicit conversion at boundaries.
- Iterators and standard collections where they improve correctness without obscuring behavior.
- `Arc`, `Mutex`, `RwLock`, channels, and atomics only with deliberate ownership/concurrency reasoning.

Avoid unnecessary `.unwrap()`, `.expect()`, indexing, unchecked assumptions, and panics in production paths. If one is justified, document the invariant that makes it impossible to fail and test that invariant.

---

## C++ Semantics That Require Special Attention

### Ownership and lifetime

Do not reproduce C++ pointer patterns literally.

For every pointer/reference in the source, determine:

- Who owns the object?
- How long must it live?
- Can it be null?
- Can it be mutated?
- Can aliases coexist?
- Is ownership transferred?
- Is destruction observable?

Then choose a Rust representation that encodes those facts.

### Undefined behavior

Treat C++ undefined behavior as a migration hazard, not as a contract.

Look specifically for:

- Out-of-bounds access.
- Use-after-free.
- Double-free.
- Uninitialized reads.
- Signed integer overflow.
- Invalid pointer arithmetic.
- Strict-aliasing/type-punning assumptions.
- Data races.
- Lifetime violations.
- Iterator invalidation.
- Invalid object representation.
- Null dereferences.
- Shift/division edge cases.

When the C++ behavior is undefined, choose a documented, deterministic Rust behavior unless compatibility explicitly requires otherwise.

### Exceptions

Map exceptions by meaning, not by class hierarchy.

Distinguish:

- Expected domain failures.
- Invalid caller input.
- I/O or infrastructure failures.
- Resource exhaustion.
- Programmer invariant violations.

Use typed errors and preserve enough context for diagnosis.

### Concurrency

Do not assume that code which was "thread-safe enough" in C++ remains so after translation.

Explicitly reason about:

- `Send`/`Sync` requirements.
- Shared mutable state.
- Lock ordering.
- Deadlocks.
- Cancellation.
- Shutdown.
- Atomic memory ordering.
- Backpressure.
- Task/thread lifetime.
- Poisoning and recovery semantics.

Prefer message passing or ownership transfer when it simplifies the concurrency model.

### ABI, wire, and binary formats

Treat all externally visible formats as contracts.

For each format, test:

- Field order.
- Width and signedness.
- Endianness.
- Alignment/padding.
- Encoding.
- Versioning.
- Optional fields.
- Malformed input.
- Round-trip behavior.

Do not use Rust `repr` tricks or memory reinterpretation as a substitute for a properly defined serialization format.

---

## Testing Requirements

Every migrated component must have tests appropriate to its risk.

### Minimum

- Existing relevant tests continue to pass or are faithfully ported.
- New tests cover newly encoded invariants.
- Boundary cases are tested.
- Error paths are tested.
- Regression tests are added for migration-discovered bugs.

### Higher-risk components

Use additional techniques where appropriate:

- Property-based tests.
- Fuzzing for parsers and untrusted input.
- Differential tests against the C++ implementation.
- Stress tests for concurrency.
- Sanitizer-assisted testing of the legacy C++ side.
- Benchmarks and profiling.
- Fault injection.
- Long-running soak tests.

Tests must verify externally meaningful behavior, not merely implementation details.

---

## Error Handling

Production errors should be:

- Typed where useful.
- Actionable.
- Context-rich.
- Stable enough for callers to classify.
- Free from accidental leakage of secrets or sensitive data.

Do not log:

- Passwords.
- Tokens.
- Private keys.
- Credentials.
- Full sensitive payloads.

Do not convert all errors to strings prematurely.

At application boundaries, produce appropriate exit statuses, HTTP/RPC status codes, or protocol-level errors.

---

## Observability

A production-standard migration must preserve or improve diagnostics.

Where relevant, provide:

- Structured logs.
- Metrics.
- Traces.
- Correlation/request IDs.
- Startup/shutdown diagnostics.
- Resource and queue visibility.
- Useful error context.

Avoid logging in hot loops without evidence that the volume is acceptable.

Instrumentation must not materially alter correctness or create hidden synchronization bottlenecks.

---

## Performance

Do not optimize by intuition alone.

For performance-sensitive migrations:

1. Establish a C++ baseline.
2. Define representative workloads.
3. Benchmark Rust under equivalent conditions.
4. Profile meaningful regressions.
5. Optimize only the demonstrated bottleneck.
6. Re-run correctness and benchmark suites.

Do not introduce unsafe code to recover performance.

Accept a small performance regression only when it is understood, measured, and justified by a concrete production requirement.

---

## Dependencies and Supply Chain

Prefer mature, actively maintained crates with:

- Appropriate licensing.
- Clear ownership/maintenance.
- Small, understandable dependency surface.
- Good security history.
- Compatible MSRV/toolchain policy.
- Safe public APIs.

Before adding a dependency, check whether the standard library or existing workspace dependencies already solve the problem.

Keep dependency versions reproducible through the lockfile where appropriate.

Audit dependency changes for:

- Transitive dependency growth.
- Native code.
- Build scripts.
- Network access during builds.
- Unsafe implementation details.
- License implications.
- Known vulnerabilities.

---

## Code Review Checklist

A migration PR is not ready until reviewers can answer "yes" to the applicable items:

- [ ] Rust 2024 edition is used.
- [ ] No production `unsafe` Rust was introduced.
- [ ] C++ behavior was characterized before translation.
- [ ] Ownership and lifetimes are explicit and sound.
- [ ] Error behavior is intentionally mapped.
- [ ] Concurrency behavior is understood and tested.
- [ ] External formats/ABIs are preserved where required.
- [ ] Tests cover normal, boundary, and failure cases.
- [ ] Differential testing was used where practical.
- [ ] Performance was measured for sensitive paths.
- [ ] Logging/metrics/tracing are adequate.
- [ ] No secrets or sensitive data are exposed in logs.
- [ ] Clippy warnings are resolved rather than suppressed.
- [ ] Documentation explains non-obvious invariants.
- [ ] Build/release tooling works without unnecessary C++ dependencies.
- [ ] Dead migration scaffolding is removed.
- [ ] CI gates the relevant standards.
- [ ] The migration tracker is updated.

---

## CI Quality Gates

The Rust portion of the repository should fail CI when applicable checks fail.

At minimum, establish gates for:

1. Formatting.
2. Compilation/checking.
3. Tests.
4. Clippy with warnings treated as errors.
5. Rust 2024 edition.
6. No unsafe code in production crates.
7. Documentation/build checks for public libraries.
8. Dependency/security policy checks.
9. Benchmarks or performance thresholds for designated critical paths.

Do not make migration-specific CI exceptions permanent. Every temporary exception needs an owner and removal criterion.

---

## Migration Tracking

Track each component with states such as:

- `Not assessed`
- `Assessed`
- `Characterized`
- `Rust implementation started`
- `Rust implementation validated`
- `Shadow/differential validation`
- `Production rollout`
- `C++ removed`
- `Completed`

For each component record, when relevant:

- Scope.
- Dependencies.
- Behavioral risks.
- Compatibility constraints.
- Performance baseline.
- Test coverage.
- Known gaps.
- Rollout plan.
- Owner.
- Exit criteria.

---

## Definition of Done

A component is considered migrated only when all applicable conditions are satisfied:

1. Its production path is implemented in Rust 2024.
2. The implementation requires no `unsafe` Rust.
3. Behavior is characterized and validated.
4. Tests cover important success and failure modes.
5. Error handling is production-appropriate.
6. Concurrency and ownership invariants are explicit.
7. Observability is sufficient for operation and diagnosis.
8. Performance is acceptable based on measurement.
9. Security and dependency review is complete.
10. CI enforces the applicable quality gates.
11. The old C++ implementation is no longer required.
12. Documentation and migration tracking are updated.

The ultimate repository-level definition of done is:

> **The C++ implementation has been replaced by maintainable, production-standard Rust 2024, with equivalent or intentionally improved behavior, and the production Rust codebase contains no `unsafe` Rust.**
