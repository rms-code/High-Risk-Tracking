function Get-IPGeolocation
{
	Param
	(
		[string]$IPAddress
	)
	
	$request = Invoke-RestMethod -Method Get -Uri "http://geoip.nekudo.com/api/$IPAddress"
	
	[PSCustomObject]@{
		IP = $request.IP
		City = $request.City
		Country = $request.Country.Name
		Code = $request.Country.Code
		Location = $request.Location.Latitude
		Longitude = $request.Location.Longitude
		TimeZone = $request.Location.Time_zone
	}
}

#Get ESET
$uri1 = "graylog rest input"
$file = "C:\keys\tempps.txt"
$user = "grayloguser"
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
$s = Invoke-RestMethod -Method GET -Uri $uri1 -Credential $creds -ContentType application/json -Header @{ "Accept" = "application/json" }
$s1 = ($s.messages).message

	foreach ($entry in $s1)
	{
		$Date = $entry.timestamp -replace "T\d\d:\d\d:\d\d.\d\d\dZ", "" -replace '"timestamp":', "" -replace '"', ""
		$Time = $entry.timestamp -replace '"timestamp":"', "" -replace "\d\d\d\d-\d\d-\d\dT", "" -replace ".{5}$"
		$devid = "ESET"
		$attack = $entry.ESETThreatType -replace '"threat_name":', "" -replace '"', ""
		$srcipcheck = $entry.ESETIP -replace '"ipv4":', "" -replace '"hostname":', "" -replace '"', ""
		if ($srcipcheck -match "[a-zA-Z]") {$srcip = (Resolve-DnsName $srcipcheck).IPAddress }else { $srcip = $entry.ESETIP -replace '"ipv4":', "" -replace '"hostname":', "" -replace '"', "" }
		$subtype = $entry.ESETThreatName -replace '"threat_level":', "" -replace '"', ""
		$action = $entry.ESETAction	-replace '"',""
		
		$insertquery =
	"
		INSERT INTO [dbo].[highpro] 
	           ([Date]
		       ,[Time] 
			   ,[devid]
	           ,[attack]
			   ,[srcip]
			   ,[subtype]
			   ,[action]) 
	    VALUES 
	         ('$Date'
		     ,'$Time'
			 ,'$devid'
	         ,'$attack'
			 ,'$srcip'
			 ,'$subtype'
			 ,'$action') 

		GO
		"
		Invoke-SQLcmd -ServerInstance 'SQLSERVER\INSTANCE' -query $insertquery -database 'databasename'
	}


#Get Malwarebytes
$uri2 = "graylog rest input"
$file = "C:\keys\tempps.txt"
$user = "grayloguser"
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
$sd = Invoke-RestMethod -Method GET -Uri $uri2 -Credential $creds -ContentType application/json -Header @{ "Accept" = "application/json" }
$sd1 = ($sd.messages).message

	foreach ($entry in $sd1)
	{
		$Date = $entry.MWBtimestamp -replace "T\d\d:\d\d:\d\d-\d\d\:\d\d", "" -replace '"time":',"" -replace '"',""
		$Time = $entry.MWBtimestamp -replace '"time":"', "" -replace "\d\d\d\d-\d\d-\d\dT", "" -replace ".{7}$"
		$devid = "Malwarebytes"
		$attack = $entry.MWBthreatname  -replace '"threat_name":',"" -replace '"', ""
		$srcip = $entry.MWBHostIP -replace '"ip_address":', "" -replace '"', ""
		$hostname = $entry.MWBhostname -replace '"host_name":',"" -replace '"', ""
		$dstip = $entry.MWBobject -replace '"object":',"" -replace '"', ""
		$subtype = $entry.MWBthreatlevel -replace '"threat_level":',"" -replace '"', ""
		$action = $entry.MWBthreataction -replace '"action":',"" -replace '"', ""
		$msg = $entry.MWBprocess -replace '"operation":',"" -replace '"',""
		$countrydst = (Get-IPGeolocation $entry.MWBobject).Country
	
		$insertquery =
	"
		INSERT INTO [dbo].[highpro] 
	           ([Date]
		       ,[Time] 
			   ,[devid]
			   ,[msg]
	           ,[attack]
			   ,[srcip]
			   ,[hostname]
			   ,[dstip]
			   ,[subtype]
			   ,[action]
			   ,[countrydst]) 
	    VALUES 
	         ('$Date'
		 	 ,'$Time'
			 ,'$devid'
			 ,'$msg'
	         ,'$attack'
			 ,'$srcip'
			 ,'$hostname'
			 ,'$dstip'
			 ,'$subtype'
			 ,'$action'
			 ,'$countrydst') 

		GO
		"
		Invoke-SQLcmd -ServerInstance 'SQLSERVER\INSTANCE' -query $insertquery -database 'databasename'
	}

#Get Airlock Digital
$uri3 = "graylog rest input"
$file = "C:\keys\tempps.txt"
$user = "grayloguser"
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
$sa = Invoke-RestMethod -Method GET -Uri $uri3 -Credential $creds -ContentType application/json -Header @{ "Accept" = "application/json" }
$sa1 = ($sa.messages).message | ?{ $_.Event -eq "Blocked Execution" }

foreach ($entry in $sa1)
{
	$Date = $entry.airlockeventdate -replace "T.*", ""
	$Time = $entry.airlockeventdate -replace "\d\d\d\d-\d\d-\d\dT", "" -replace ".{13}$"
	$devid = "AIRLOCK"
	$srcipcheck = $entry.Hostname
	if ($srcipcheck -match "[a-zA-Z]") { $srcip = (Resolve-DnsName $srcipcheck).IPAddress }else { $srcip = $entry.Hostname }
	$hostname = $entry.User
	$subtype = $entry.ChildPolicyName
	$action = $entry.Event
	$eventtype = $entry.File
	
	$insertquery =
	"
		INSERT INTO [dbo].[highpro] 
	           ([Date]
		       ,[Time] 
	           ,[devid]
			   ,[srcip]
			   ,[hostname]
			   ,[subtype]
			   ,[action]
			   ,[eventtype]) 
	    VALUES 
	         ('$Date'
		     ,'$Time'
	         ,'$devid' 
			 ,'$srcip'
			 ,'$hostname'
			 ,'$subtype'
			 ,'$action'
			 ,'$eventtype') 

		GO
		"
	Invoke-SQLcmd -ServerInstance 'SQLSERVER\INSTANCE' -query $insertquery -database 'databasename'
}

#Get UTM from foritgate(s)
$uri4 = "graylog rest input"
$file = "C:\keys\tempps.txt"
$user = "grayloguser"
$creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
$sv = Invoke-RestMethod -Method GET -Uri $uri4 -Credential $creds -ContentType application/json -Header @{ "Accept" = "application/json" }
$sv1 = ($sv.messages).message
$sv1inj = $sv1 | select emailDATE, emailTIME, devid, attack, msg, srcip, dstport, hostname, dstip, subtype, action, eventtype, ref

		foreach ($entry in $sv1)
		{
		$Date = $entry.emailDATE
		$Time = $entry.emailTIME
		$devid = $entry.devid -replace '"',""
		$attack = $entry.attack
		$msg = $entry.msg
		$srcip = $entry.srcip
		$dstport = $entry.dstport
		$hostname = $entry.hostname
		$dstip = $entry.dstip
		$subtype = $entry.subtype -replace '"',""
		$action = $entry.action -replace '"',""
		$eventtype = $entry.eventtype -replace '"', ""
		$countrysrc = (Get-IPGeolocation $entry.srcip).Country
		$countrydst = (Get-IPGeolocation $entry.dstip).Country
		$ref = $entry.ref

	$insertquery =
	"
		INSERT INTO [dbo].[highpro] 
	           ([Date]
		       ,[Time] 
	           ,[devid]
	           ,[attack]
			   ,[msg]
			   ,[srcip]
			   ,[dstport]
			   ,[hostname]
			   ,[dstip]
			   ,[subtype]
			   ,[action]
			   ,[eventtype]
			   ,[ref]
			   ,[countrysrc]
			   ,[countrydst]) 
	    VALUES 
	         ('$Date'
		     ,'$Time' 
	         ,'$devid' 
	         ,'$attack'
			 ,'$msg'
			 ,'$srcip'
			 ,'$dstport'
			 ,'$hostname'
			 ,'$dstip'
			 ,'$subtype'
			 ,'$action'
			 ,'$eventtype'
		 	 ,'$ref'
		 	 ,'$countrysrc'
			 ,'$countrydst') 

		GO
		"
		Invoke-SQLcmd -ServerInstance 'SQLSERVER\INSTANCE' -query $insertquery -database 'databasename'
}