#!/bin/sh
# Build a throwaway home for recording: a copy of the fixture, the freshly built
# ./flywheel, no personal config and no personal paths. Prints the directory.
# usage: make clean && make && d=$(demo/prepare.sh) && (cd "$d" && FWDEMO=$d vhs /path/to/demo/demo.tape)
set -eu
repo=$(cd "$(dirname "$0")/.." && pwd)
# /private/tmp, not $TMPDIR: tracebacks and dialogs show absolute paths
d=$(mktemp -d /private/tmp/fwdemo.XXXXXX)
mkdir -p "$d/bin" "$d/home/textstats"
cp "$repo/flywheel" "$d/bin/flywheel"
cp "$repo/demo/textstats/"*.py "$repo/demo/textstats/pyproject.toml" "$d/home/textstats/"
# the recording is published: list numeric ids instead of the real account name
printf '#!/bin/sh\nexec /bin/ls -n "$@"\n' > "$d/bin/ls"
chmod +x "$d/bin/ls"
cat > "$d/env.sh" <<EOF
cd "$d/home/textstats"
exec env -i HOME="$d/home" USER=demo LOGNAME=demo SHELL=/bin/bash TERM=xterm-256color \\
  LANG=en_US.UTF-8 PATH="$d/bin:/opt/homebrew/bin:/usr/bin:/bin" PS1='\$ ' \\
  bash --noprofile --norc
EOF
echo "$d"
