rule MimikatzStrings {
    meta:
        description = "Mimikatz credential dumping tool indicators"
        mitre = "T1003.001"
        confidence = "HIGH"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "lsadump::sam" nocase
        $s3 = "privilege::debug" nocase
        $s4 = "mimikatz" nocase
    condition:
        any of them
}
