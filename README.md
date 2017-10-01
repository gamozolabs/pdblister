# Summary

This is a tiny project to be a quick alternative to symchk for generating
manifests. This mimics symchk of the form `symchk /om manifest /r <path>`
but only looks for MZ/PE files.

Due to symchk doing some weird things it can often crash or get stuck in
infinite loops. Thus this is a stricter (and much faster) alternative.

The output manifest is compatible with symchk and thus symchk is currently
used for the actual download. To download symbols after this manifest
has been generated use `symchk /im manifest /s <symbol path>`

# Usage

Usage:

    pdblister [manifest | download | clean] <filepath>
 
    === Create manifest === 
    
        pdblister manifest <filepath>

        This command takes in a filepath to recursively search for files that
        have a corresponding PDB. This creates a file called `manifest` which
        is compatible with symchk.
        
        For example `pdblister manifest C:\\windows` will create `manifest`
        containing all of the PDB signatures for all of the files in
        C:\\windows.

    === Download from manifest ===

        pdblister download

        This command takes no parameters. It simply downloads all the PDBs
        specified in the `manifest` file from msdl.microsoft.com to a folder
        called `symbols` in the current directory. To change this, change the
        SYMPATH global in the code.

    === Clean ===

        pdblister clean

        This command removes the `manifest` file as well as the symbol folder

# Future

More configuration could be done through command line parameters. Such as
number of threads for downloads and symbol paths.

Randomizing the order of the files in the manifest would make downloads more
consistant by not having any filesystem locality bias in the files.

Deduping the files in the manifests could also help, but this isn't a big
deal *shrug*

# Performance

This tool tries to do everything in memory if it can. Lists all files first
then does all the parsing (this has random accesses to files without mapping so
it could be improved, but it doesn't really seem to be an issue, this random
access only occurs if it sees an MZ and PE header and everything is valid).

It also generates the manifest in memory and dumps it out in one swoop, this is
one large bottleneck original symchk has.

Then for downloads it splits the manifest into chunks to pass to symchk. By
default symchk only peaks at about 3-4 Mbps of network usage, but when split
up (into 64 threads), I can max out my internet at 180 Mbps.

Look how damn fast this stuff is!

```
On an offline machine:

PS C:\users\pleb\Downloads> .\pdblister.exe clean
Time elapsed: 0 seconds
PS C:\users\pleb\Downloads> .\pdblister.exe manifest C:\
Generating file listing...
Done!
Parsed 398632 of 398632 files (23051 pdbs)
Time elapsed: 104 seconds

On an online machine:
C:\dev\pdblister>cargo run --release download
    Finished release [optimized] target(s) in 0.0 secs
     Running `target\release\pdblister.exe download`
Trying to download 23051 PDBs
Time elapsed: 120 seconds
```

