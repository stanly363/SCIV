rule SUNBURST_Backdoor {
    strings:
        $a = "SolarWinds.Orion.Core.BusinessLayer" ascii wide
    condition:
        $a
}




