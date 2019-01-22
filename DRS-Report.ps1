Import-module VMware.VimAutomation.Core
Set-PowerCLIConfiguration -DefaultVIServerMode multiple -InvalidCertificateAction ignore -Confirm:$false
Connect-VIServer -Server s930a8015

$strOutputFilespec = "D:\SCRIPT\DRS\DRSrules_export.csv"
 

Get-View -ViewType ClusterComputeResource -Property Name, ConfigurationEx | %{

    if ($_.ConfigurationEx.Rule -ne $null) {
        $viewCurrClus = $_
        $viewCurrClus.ConfigurationEx.Rule | %{
            $oRuleInfo = New-Object -Type PSObject -Property @{
                ClusterName = $viewCurrClus.Name
                RuleName = $_.Name
                RuleType = $_.GetType().Name
                bRuleEnabled = $_.Enabled
                bMandatory = $_.Mandatory
            } ## end new-object
 
            ## add members to the output object, to be populated in a bit
            "bKeepTogether,VMNames,VMGroupName,VMGroupMembers,AffineHostGrpName,AffineHostGrpMembers,AntiAffineHostGrpName,AntiAffineHostGrpMembers".Split(",") | %{Add-Member -InputObject $oRuleInfo -MemberType NoteProperty -Name $_ -Value $null}
 

            switch ($_){

                {$_ -is [VMware.Vim.ClusterVmHostRuleInfo]} {
                    $oRuleInfo.VMGroupName = $_.VmGroupName

                    $oRuleInfo.VMGroupMembers = (Get-View -Property Name -Id ($viewCurrClus.ConfigurationEx.Group | ?{($_ -is [VMware.Vim.ClusterVmGroup]) -and ($_.Name -eq $oRuleInfo.VMGroupName)}).Vm | %{$_.Name}) -join ","
                    $oRuleInfo.AffineHostGrpName = $_.AffineHostGroupName

                    $oRuleInfo.AffineHostGrpMembers = if ($_.AffineHostGroupName -ne $null) {(Get-View -Property Name -Id ($viewCurrClus.ConfigurationEx.Group | ?{($_ -is [VMware.Vim.ClusterHostGroup]) -and ($_.Name -eq $oRuleInfo.AffineHostGrpName)}).Host | %{$_.Name}) -join ","}
                    $oRuleInfo.AntiAffineHostGrpName = $_.AntiAffineHostGroupName

                    $oRuleInfo.AntiAffineHostGrpMembers = if ($_.AntiAffineHostGroupName -ne $null) {(Get-View -Property Name -Id ($viewCurrClus.ConfigurationEx.Group | ?{($_ -is [VMware.Vim.ClusterHostGroup]) -and ($_.Name -eq $oRuleInfo.AntiAffineHostGrpName)}).Host | %{$_.Name}) -join ","}
                    break;
                } ## end block

                {($_ -is [VMware.Vim.ClusterAffinityRuleSpec]) -or ($_ -is [VMware.Vim.ClusterAntiAffinityRuleSpec])} {
                    $oRuleInfo.VMNames = if ($_.Vm.Count -gt 0) {(Get-View -Property Name -Id $_.Vm | %{$_.Name}) -join ","}
                } ## end block
                {$_ -is [VMware.Vim.ClusterAffinityRuleSpec]} {
                    $oRuleInfo.bKeepTogether = $true
                } ## end block
                {$_ -is [VMware.Vim.ClusterAntiAffinityRuleSpec]} {
                    $oRuleInfo.bKeepTogether = $false
                } ## end block
                default {"none of the above"}
            } ## end switch
 
            $oRuleInfo
        } ## end foreach-object
    } ## end if
} | Export-Csv -NoTypeInformation $strOutputFilespec
$from = "prasad.mahudapathi@rwe.com"
$to = "t.pohl@rwe.com"
$cc = "srikanth.puranam@rwe.com,venkata.lanka@rwe.com,vamshi.krishna@rwe.com"
$bcc = "prasad.mahudapathi@rwe.com"
$att = "D:\SCRIPT\DRS\DRSrules_export.csv"
$smtp = "mailgw2.rwe.com"
$subject = "DRS Report"
$body = @"
Hi Thomas,

Please find the attached DRS report.  


Kind Regards,

Prasad Mahudapathi
Physical\Virtual Infrastructure (MFP-D)

"@
Send-MailMessage -From $from -To $to -cc $cc -Bcc $bcc -Subject $subject -Body $body -Attachment $att -Smtpserver $smtp