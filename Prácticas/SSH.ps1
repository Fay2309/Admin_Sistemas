. "$PSScriptRoot\Funciones.ps1"
clear
$op = 0

While ($op -eq 0) {
    Write-Output "=== Servidor SSH, ingrese las opciones que desea realizar=="
    Write-Output "1.- Instalar e inicar SSH 
2.- Reiniciar SSH
3.- Aplicar reglas de Firewall
4.- Verificar cuentas SSH
5.- Obtener Información de cuentas
6.- Agregar cuentas SSH
7.- Eliminar cuentas SSH
8.- Salir"
    
    $op2 = Read-Host 
    switch($op2) {
        1 {$sshservice = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
        if ($sshservice) {
            Write-Host "`nEl servicio SSH ya está instalado, inciando servicio..."
            Start-Service sshd
            Write-Host "Aplicando inicio autómatico..."
            Set-Service -Name sshd -StartupType Automatic

            Write-Host "SSH configurado correctamente... `n"
        } else {
            Write-Host "El servicio SSH no está instalado, procediendo instalación..."

            Add-WindowsCapability -Online -Name OpenSSH.Server
            Start-Service sshd
            Write-Host "Aplicando inicio autómatico..."
            Set-Service -Name sshd -StartupType Automatic

            Write-Host "SSH instalado y configurado correctamente... `n"
         }
       }
        2 {"`nReiniciando servicio SSH..."
        Restart-Service sshd
        "Servicio SSH reiniciado correctamente...`n"
       }
        3 { $firewallrule = Get-NetFirewallRule -DisplayName "Allow SSH" -ErrorAction SilentlyContinue
        if ($firewallrule) {
            "`nLa regla ya está creada, no se creará otra vez...`n"
        } else {
            "`nAplicando regla SSH..."
             New-NetFirewallRule -Name sshd -DisplayName "Allow SSH" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
             "Regla aplicada correctamente...`n"
        }
       }
        4 {Write-Host "`nCuentas disponibles para SSH..."
            Get-WmiObject Win32_UserAccount -filter "LocalAccount=True" | Select-Object Name,FullName,Disabled | Format-Table -AutoSize | Out-Host
       }
        5 {Info_User}
        6 {Add_User}
        7 {Delete_User}
        8 {"`nSaliendo del script..." 
        exit 0}
        default {"`nFavor de introducir un valor valido entre 1 y 8...`n"}
    }

}
