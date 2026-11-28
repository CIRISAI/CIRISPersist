# v62.0.0 release branch: working notes

Branch `release/v62`. These notes are tracked and pushed so the state of the
release survives any one machine. Add to `LOG.md` at every step; push at
least daily.

| File | What |
|---|---|
| `LOG.md` | Dated working log: decisions, who made them, what was run. |
| `PLAN.md` | The strategy for finishing v62 on the kernel release, and the boundary of what ships. |
| `DELETE_LIST.md` | Every place the build line still decides a rule over rows itself. Deleted, not ported. |
| `HOST_VERBS.md` | Host-facing methods and capsule ops tied to rules that go. Each change needs Eric. |
| `KERNEL_MAP.md` | Persist's rule groups mapped to the kernel crate's public functions (work-in-progress branch). |

## Where things are

- **This branch** starts at the rescued build line (`rescue/v62/wint`, one
  snapshot commit on `v62-int3` 01ba09cb). Nothing on it has been built or
  run since the snapshot.
- **Lane work** not yet integrated is on `rescue/v62/<lane>` branches, one
  snapshot commit each. It is sorted against the kernel release as a whole
  before any of it is used: lane work that adds or refines a rule persist
  will no longer decide is dropped, not integrated.
- **Pins this release will take:** a Constitution `rc23` pre-release tag
  (which vendors the kernel tag), the Verify release cut on it, and
  `ciris-kernel` 0.5.0. None of the three is tagged yet. The build line
  still pins kernel 0.2.2.

## Rules of the branch

- Persist stores rows, checks one row's bytes and shape at the door, and
  presents rows to `ciris_kernel`. It decides no rule over a set of rows and
  keeps no policy table.
- No refactor code is written before the kernel release is tagged.
- Never `git commit --no-verify`. Cargo runs go through
  `scripts/cargo_guard.sh`. Every change is tested on sqlite and postgres.
- Refusal tokens, family names and vocabulary words come from the
  Constitution repo. None is invented here.
