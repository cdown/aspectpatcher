Patch aspect ratio bytes in binary files. Mostly useful for games.

Takes two args:

- `-t`, the ratio/res/hex bytes to find
- `-r`, the ratio/res/hex bytes to replace with

For example, to patch AC Mirage to not have black bars on ultrawide:

    % aspectpatcher -t 16:9 -r 3840x1600 ACMirage.exe

## Why not just use a hex editor?

A naive search/replace across the entire file is risky. The 4-byte float
representation of an aspect ratio can appear in many places, like as part of
CPU instructions, addresses, or unrelated data.

This tool parses the PE headers and only patches within data sections
(`.rdata`, `.data`, `.xdata`, etc.), skipping code sections, resources, and
metadata. For AC Mirage, for example, a naive scan of 16:9 ratios finds 37
matches, but only 2 are actual aspect ratio constants in data sections,
modifying the others may do unknown things to the code flow.
