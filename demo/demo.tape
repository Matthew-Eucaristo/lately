# Record with: vhs demo/demo.tape   (run from the repository root)
# Everything shown is replayed from demo/sample: no real log content.
Output demo/demo.gif
Set Shell bash
Set FontSize 13
Set Width 1200
Set Height 600
Set Padding 16
Set TypingSpeed 50ms
Set Framerate 6

Hide
Type "source demo/setup.sh && clear" Enter
Sleep 8s
Show

Type "lately --replay sample" Sleep 300ms Enter
Sleep 3s

# Reach further back one step, then come back: nothing is read twice.
Type "t" Sleep 2s
Type "T" Sleep 1.2s

# The window that flashed: what started it (from the replayed capture).
Type "A" Sleep 4s
Escape Sleep 800ms

# The VPN's root daemon: its card links the install and the same developer.
Down Sleep 400ms
Down Sleep 400ms
Down Sleep 400ms
Down Sleep 400ms
Down Sleep 1.2s
Enter Sleep 4.5s
Down Sleep 800ms
Enter Sleep 3s
Escape Sleep 800ms
Escape Sleep 800ms

# Follow while reproducing a bug: new rows arrive on top.
Type "f" Sleep 11s
Type "f" Sleep 800ms

# Why did my Mac restart last night?
Type "R" Sleep 5s
Escape Sleep 800ms
Type "q" Sleep 1.2s

Hide
Type "cd / && rm -rf /tmp/lately-demo" Enter
Sleep 1s
