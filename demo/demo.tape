# Real, uncut run of the interactive TUI. Record with demo/record.sh.
# vhs cannot branch and the model asks for a varying number of approvals, so each
# round below waits for a dialog or the final line, then presses y ("Yes"; the
# dialog's default is "No"). A space first, because a long command must be scrolled
# to its end before it can be allowed. Each key is followed by Backspace, so on the
# idle input box (spare rounds, which hold the finished screen) it leaves nothing.
# More dialogs than rounds fails the take.
Output demo.mp4

Set Shell bash
Set FontSize 22
Set Width 1280
Set Height 800
Set Padding 16
Set Framerate 30
Set TypingSpeed 25ms
Set Theme "Catppuccin Mocha"
Set WaitTimeout 90s

Hide
Type '. "$FWDEMO/env.sh"'
Enter
Sleep 1s
Type "clear"
Enter
Sleep 500ms
Show

Sleep 500ms
Type "flywheel -T 20 -W 120 --transcript ../transcript.jsonl"
Enter
Wait+Screen /initialize .flywheel.md/
Sleep 1500ms
Type "n"
Wait+Screen /Type a message/
Sleep 700ms
Type "python3 -m unittest fails. Fix textstats.py so all tests pass. Do not edit test_textstats.py. Run the tests to confirm."
Sleep 1s
Enter

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /Do you want to proceed|✓ done|✗ /
Sleep 1300ms
Space
Backspace
Sleep 200ms
Type "y"
Backspace
Sleep 500ms

Wait+Screen /✓ done/
Sleep 4s
