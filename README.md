# Summary

This is a tiny project to be a quick alternative to symchk for generating
manifests. This mimics symchk of the form `symchk /om manifest /r <path>`
but only looks for MZ/PE files.

Due to symchk doing some weird things it can often crash or get stuck in
infinite loops. Thus this is a stricter (and much faster) alternative.

The output manifest is compatible with symchk and thus symchk is currently
used for the actual download. To download symbols after this manifest
has been generated use `symchk /im manifest /s <symbol path>`

# Future

In the future this will take parameters (not many, just a path and an output
filename).

I also want to make it so you can split the manifest into n-pieces or n-sized
chunks, and then do symchk download in parallel, as symchk is a bit slow
(but it has to do some decompression so it's fair).

I don't plan on making this do the full symchk chain of downloading files and
extracting them and maintaining the sympath stuff. I've done it before and it
just wasn't worth it. The slow part is almost always just listing the directory

# Performance

This tool tries to do everything in memory if it can. Lists all files first
then does all the parsing (this has random accesses to files without mapping so
it could be improved, but it doesn't really seem to be an issue, this random
access only occurs if it sees an MZ and PE header and everything is valid).

It also generates the manifest in memory and dumps it out in one swoop, this is
one large bottleneck original symchk has.

Look how damn fast this stuff is!

```
PS C:\dev\pdblister> Measure-Command { cargo run --release }
    Finished release [optimized] target(s) in 0.0 secs
     Running `target\release\pdblister.exe`


Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 2
Milliseconds      : 516
Ticks             : 25164749
TotalDays         : 2.91258668981481E-05
TotalHours        : 0.000699020805555555
TotalMinutes      : 0.0419412483333333
TotalSeconds      : 2.5164749
TotalMilliseconds : 2516.4749



PS C:\dev\pdblister> Measure-Command { symchk /q /om manifest /r C:\windows\system32 /s C:\THISDOESNOTEXIST }


Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 8
Milliseconds      : 995
Ticks             : 89959488
TotalDays         : 0.000104119777777778
TotalHours        : 0.00249887466666667
TotalMinutes      : 0.14993248
TotalSeconds      : 8.9959488
TotalMilliseconds : 8995.9488
```

