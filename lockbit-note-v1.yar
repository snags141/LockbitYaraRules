rule LOCKBIT_Note_PE_v1

{

    strings:

 

        $onion = /http:\/\/lockbit[a-z0-9]{9,49}.onion/ ascii wide

        $note1 = "restore-my-files.txt" nocase ascii wide

        $note2 = /lockbit[_-](ransomware|note)\.hta/ nocase ascii wide

        $v2 = "LockBit_2_0_Ransom" nocase wide

 

    condition:

 

        (uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)

        and $onion

        and (all of ($note*)) and not $v2
}
