Patch aspect ratio bytes in binary files. Mostly useful for games.

Takes two args:

- `-t`, the ratio/res/hex bytes to find
- `-r`, the ratio/res/hex bytes to replace with

For example, to patch AC Mirage to not have black bars on ultrawide:

    % aspectpatcher -t 16:9 -r 3840x1600 ACMirage.exe
