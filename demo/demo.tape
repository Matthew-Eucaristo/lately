# Record with: vhs demo/demo.tape   (run from the repository root)
# Everything shown is replayed from demo/sample: no real log content.
Output demo/demo.gif
Set Shell bash
Set FontSize 13
Set Width 1200
Set Height 580
Set Padding 16
Set TypingSpeed 50ms
Set Framerate 8

Hide
Type "source demo/setup.sh && clear" Enter
Sleep 8s
Show

Type "lately --replay sample" Sleep 300ms Enter
Sleep 3.5s

# The window that flashed: what started it (from the replayed capture).
Type "A" Sleep 4s
Escape Sleep 800ms

# The VPN install: a system extension and a root daemon, linked to it.
Down Sleep 500ms
Down Sleep 500ms
Down Sleep 500ms
Down Sleep 2s
Enter Sleep 4.5s
Escape Sleep 800ms
Down Sleep 2.5s

# Why did my Mac restart last night?
Type "R" Sleep 4.5s
Escape Sleep 800ms

# Lower the floor to see context rows, then quit.
Type "s" Sleep 400ms
Type "s" Sleep 400ms
Type "s" Sleep 2.5s
Type "q" Sleep 1.5s

Hide
Type "cd / && rm -rf /tmp/lately-demo" Enter
Sleep 1s
