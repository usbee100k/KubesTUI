# vt10x (vendored)

Copy of github.com/hinshun/vt10x at v0.0.0-20220301184237-5011da428d02
(MIT, see LICENSE), with one KubesTUI patch so the embedded terminal can
keep scrollback:

- `WithScrollback(fn)` option (vt.go) and `State.scrollOut` (state.go):
  `scrollUp` passes each line that scrolls off the top of the main screen
  to `fn` before clearing it. The alternate screen (vim, htop, less) is
  excluded, matching how real terminals build scrollback.

Patched spots are marked `[KubesTUI patch]`.
