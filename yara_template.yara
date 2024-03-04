rule PE_CSharp {
    
    meta: 
        last_updated = "2021-10-15"
        author = "PMAT"
        description = "A sample Yara rule for PMAT"

    strings:
        // Fill out identifying strings and other criteria
        $string1 = "p0w3r0verwh3lm1ng" ascii
        $string2 = "mscorlib"
        $PE_magic_byte = "MZ"

    condition:
        // Fill out the conditions that must be met to identify the binary
        $PE_magic_byte at 0 and
        ($string1 or $string2)
        //any of them
}