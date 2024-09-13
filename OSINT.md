# OSINT
* [General](#General)
* [Google fu / dorks](#Google-fu-/-dorks)
* [Host Information](#Host-Information)
  * [Mail](#Mail)
* [Hunting usernames](#Hunting-usernames)
* [Hunting passwords & credentials](#Hunting-passwords-and-credentials)
* [Hunting for personal information](#Hunting-for-personal-information)
* [Web](#Web)
  * [General Info](#General-Info)
  * [Hunting subdomains](#Hunting-subdomains)
* [Image](#Image)
  * [Reverse Image Searching](#Reverse-Image-Searching)
  * [EXIF Data](#EXIF-Data)
* [File](#File)
* [Social media](#Social-media)
* [Business](#Business)
* [Wireless](#Wireless)
* [Cloud](#Cloud)
  * [Azure](#Azure) 
* [Automating-OSINT-Example](#Automating-OSINT-Example)

## General
- Dos facetas principales del reconocimiento: organizativa y técnica.
- La recolección de información puede realizarse de forma pasiva o activa.

#### OSINT Frameworks
- https://github.com/lanmaster53/recon-ng
- https://www.maltego.com/
- https://www.spiderfoot.net/

#### Other tools
- https://hunch.ly/

#### Motores de búsqueda
- https://www.google.com/
- https://www.bing.com/
- https://duckduckgo.com/
- https://www.baidu.com/
- https://yandex.com/

#### Buscar a través de Github
- https://github.com/search?type=code

#### Creando Sockpuppet / alias
- Configurando una anónima sockpuppet
- https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/

## Google-fu-/-dorks
- https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06
- https://www.exploit-db.com/google-hacking-database

#### Ejemplo
```
site:hackdefense.com filetype:pdf
```

#### Sitio web específico
```
searchterm site:example.com
```

#### Buscar una cadena específica
```
"search this string"
``` 

## Host-Information
#### Obtener direcciones IP de un nombre de dominio
```
dig <DOMAIN> +short
```

#### Verificar whois de cada IP
- Check who owns the IP, where is it hosted?
```
whois <IP>
```

### Correo
#### Verificar spf, dkim, dmarc, etc.
- https://github.com/a6avind/spoofcheck
```
./spoofcheck.py <DOMAIN>
```

## Búsqueda de direcciones de correo electrónico 
#### Descubrimiento de direcciones de correo electrónico o patrones
- https://hunter.io
- https://phonebook.cz

#### Verificar dirección de correo electrónico
- https://tools.emailhippo.com/
- https://email-checker.net/validate

#### theHarvester
```
theHarvester -d <DOMAIN> -b google -l 500
```

#### miniconda
- https://docs.anaconda.com/miniconda/

## Hunting nombre de usuarios
- https://namechk.com/
- https://whatsmyname.app/
- https://namecheckup.com/

#### WhatsMyName
- https://github.com/WebBreacher/WhatsMyName
```
whatsmyname -u <USERNAME>
```

#### Sherlock
- https://github.com/sherlock-project/sherlock
```
sherlock <USERNAME>
```

## Hunting Contraseñas y credenciales
- https://www.dehashed.com/
- https://leakcheck.io/
- https://snusbase.com/
- https://haveibeenpwned.com/

#### Breachparse
- https://github.com/hmaverickadams/breach-parse
```
./breach-parse.sh @<DOMAIN> password.txt
```

#### H8mail
- https://github.com/khast3x/h8mail
```
h8mail -t <EMAIL>
```

#### Consulta sin claves API contra compilación de brechas locales
```
h8mail -t <EMAIL> -bc "/opt/breach-parse/BreachCompilation/" -sk
```

#### Comprobar si hay hashes
- https://hashes.org

#### Credenciales filtradas en github
- https://github.com/zricethezav/gitleaks
```
gitleaks --repo-url=<GIT REPO URL> -v
```

## Hunting información personal
- https://www.whitepages.com/
- https://www.truepeoplesearch.com/
- https://www.fastpeoplesearch.com/
- https://www.fastbackgroundcheck.com/
- https://webmii.com/
- https://peekyou.com/
- https://www.411.com/
- https://www.spokeo.com/
- https://thatsthem.com/

### Buscar números de teléfonos
- https://www.truecaller.com/
- https://calleridtest.com/
- https://infobel.com/
- ¡También puede consultar inicios de sesión, contraseñas olvidadas y verificar el número de teléfono!

#### phoneinfoga
- https://github.com/sundowndev/phoneinfoga
```
phoneinfoga scan -n <COUNTRYCODE><PHONENUMBER>
```

## Web
### Información general
- whois / dns etc
- https://centralops.net/co/
- https://spyonweb.com/
- https://dnslytics.com/reverse-ip
- https://viewdns.info/
- https://spyonweb.com/
- https://www.virustotal.com/
- Alerta sobre cambios en el sitio web: https://visualping.io/
- Busque backlinks: http://backlinkwatch.com/index.php

#### Shodan.io
- https://shodan.io/
#### Queries
- https://github.com/jakejarvis/awesome-shodan-queries

#### censys
- https://search.censys.io/

#### Verifique versiones antiguas del sitio web / archivos
- https://web.archive.org/
- https://archive.org/

### Hunting subdominios
- Script que utiliza múltiples herramientas para enumerar subdominios: https://github.com/Gr1mmie/sumrecon

#### Hunt Dominios conectados a Azure
- [Link to Azure OSINT](#get-tenant-domains)

#### CHAOS - Project Discovery
- La mejor herramienta
- https://chaos.projectdiscovery.io/#/
- https://github.com/projectdiscovery/chaos-client

```
chaos -d <DOMAIN> -silent
```

#### Amass 
- https://github.com/OWASP/Amass
```
amass enum -d example.com
```

#### Dnsdumpster
- Herramienta de interfaz gráfica de usuario: https://dnsdumpster.com/

#### Sublister
```
sublister -domain <DOMAIN>
```

#### crt.sh
- https://crt.sh

#### Dnscan
- https://github.com/rbsec/dnscan
```
dnscan.py <DOMAIN>
```

#### DNSrecon
```
python3 dnsrecon.py -d <DOMAIN>
```

#### Gobuster
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
```
gobuster dns -d <target domain> -w <wordlist>
```

#### Otras herramientas
- https://pentest-tools.com/information-gathering/find-subdomains-of-domain#
- https://spyse.com/

### Descubra las tecnologías de sitios web
- https://builtwith.com/
- https://addons.mozilla.org/nl/firefox/addon/wappalyzer/

#### Whatwheb
```
whatweb <URL>
```

## Imagen
### Búsqueda inversa de imágenes
- https://images.google.com/
- https://yandex.com/images/
- https://tineye.com/
- Drag the image in

### EXIF Data
#### Online
- Los datos de ubicación ya son mucho más seguros, pero aún podrían obtener algo.
- http://exif.regex.info/exif.cgi

#### Exiftool
```
exiftool <img>
```

#### Identificación de ubicaciones geográficas
- https://www.geoguessr.com/
- https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/

## File
- Powermeta https://github.com/dafthack/PowerMeta
- FOCA https://github.com/ElevenPaths/FOCA

## Social media
### Twitter
- https://twitter.com/search-advanced
- https://socialbearing.com/
- https://www.twitonomy.com/
- http://sleepingtime.org/
- https://mentionmapp.com/
- https://tweetbeaver.com/
- http://spoonbill.io/
- https://tinfoleak.com/
- https://tweetdeck.com/

#### Twint
- https://github.com/twintproject/twint
```
twint -u <USER> -s <STRING>
```

### Facebook
- https://sowdust.github.io/fb-search/
- https://intelx.io/tools?tab=facebook

### Instagram
- https://wopita.com/
- https://codeofaninja.com/tools/find-instagram-user-id/
- https://www.instadp.com/
- https://imginn.com/

### Snapchat
- https://map.snapchat.com

### Reddit
- https://www.reddit.com/search

### Linkedin
- https://www.linkedin.com/

## Business
- Consúltelos en LinkedIn / Twitter / Redes sociales, etc.
- https://opencorporates.com/
- https://www.aihitdata.com/

## Wireless
- https://wigle.net/

## General
1. El descubrimiento de host tradicional aún se aplica
2. Después de que el descubrimiento de host resuelva todos los nombres, realice búsquedas de Whois para determinar dónde están alojados.
3. El espacio de IP de Microsoft, Amazon y Google generalmente indica el uso del servicio en la nube.
4. Verifique los registros MX. Estos pueden mostrar proveedores de correo alojados en la nube

## Cloud
#### Verificar bloqueos de red IP
- Azure Netblocks
  - Public: https://www.microsoft.com/en-us/download/details.aspx?id=56519 
  - US Gov: http://www.microsoft.com/en-us/download/details.aspx?id=57063 
  - Germany: http://www.microsoft.com/en-us/download/details.aspx?id=57064 
  - China: http://www.microsoft.com/en-us/download/details.aspx?id=57062
- AWS Netblocks
  - https://ip-ranges.amazonaws.com/ip-ranges.json
- GCP Netblocks
  - https://www.gstatic.com/ipranges/cloud.json

#### ip2provider
- https://github.com/oldrho/ip2provider
```
cat iplist.txt | python ip2provider.py
```

#### Azure / O365 usage
- Agregar dominio a la siguiente URL, si existe hay un tenant: 
```
https://login.microsoftonline.com/<TARGET DOMAIN>/v2.0/.well-known/openid-configuration
```

#### Uso de Google Workspace
- Intente autenticarse con una dirección de correo electrónico válida de la empresa en Gmail
- https://accounts.google.com/

#### Uso de AWS
- Verificar si se están cargando recursos desde los buckets S3
- Con burp, navegue por la aplicación web y verifique si hay llamadas a ```https://[bucketname].s3.amazonaws.com ``` or  ```• https://s3-[region].amazonaws.com/[Org Name]```

#### Uso de Box.com
- Busque portales de inicio de sesión
- https://companyname.account.box.com

### Enumerar recursos públicos
#### Cloud enum
- Es posible utilizar múltiples palabras clave `-k`.
```
python3 cloud_enum.py -k <KEYWORD>
```

### Azure
#### Verifique si el inquilino está en uso y si la federación está en uso. 
- La federación con Azure AD u O365 permite a los usuarios autenticarse usando credenciales locales y acceder a todos los recursos en la nube.
```
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
```

#### obtenga Tenant ID
```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
```

### AADinternals
- https://github.com/Gerenios/AADInternals
- https://o365blog.com/aadinternals/

#### Importar el modulo AADinternals
```
import-module .\AADInternals.psd1
```

#### Obtenga toda la información de tenant
```
Invoke-AADIntReconAsOutsider -DomainName <DOMAIN>
```

#### Obtener el nombre de Tenant, la autenticación, el nombre de la marca (generalmente el mismo que el nombre del directorio) y el nombre de dominio
```
Get-AADIntLoginInformation -UserName <RANDOM USER>@<DOMAIN>
```

#### Obtener tenant ID
```
Get-AADIntTenantID -Domain <DOMAIN>
```

#### Obtener tenant domains
```
Get-AADIntTenantDomains -Domain <DOMAIN>
```

#### Obtenga la marca de la empresa
- Browse to URL `https://login.microsoftonline.com/?whr=<DOMAIN>` and replace `<DOMAIN>` with company domain


#### Verificar si el usuario(s) existe(n) en tenant
- Hay tres métodos de enumeración diferentes para elegir:
    - Normal: hace referencia a la API GetCredentialType mencionada anteriormente. El método predeterminado.
    - Login: este método intenta iniciar sesión como el usuario.
        - OPSEC: las consultas se registrarán en el registro de inicios de sesión.
    - Autologon: este método intenta iniciar sesión como el usuario a través del punto final de inicio de sesión automático.
        - ¡Las consultas no se registran en el registro de inicios de sesión! Por lo tanto, también funciona bien para ataques de fuerza bruta y de rociado de contraseñas.
```
Invoke-AADIntUserEnumerationAsOutsider -UserName <USER UPN>

Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider -Method Normal
```

### Enumerar servicios utilizados
#### Enumerar subdominios de Azure
- https://github.com/NetSPI/MicroBurst
- Edite el archivo permutations.txt para agregar permutaciones como carrera, recursos humanos, usuarios, archivos y copias de seguridad.
```
Import-Module MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base <SHORT DOMAIN NAME> -Verbose
```

#### Enumerar Azureblobs
- Agregue permutaciones a permutations.txt como común, copia de seguridad y código en el directorio misc.
```
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
```

### Correos electrónicos válidos
#### Verificar ID de correo electrónico
- https://github.com/dievus/Oh365UserFinder
- ¡Podría recopilar una lista de correos electrónicos de algo como harvester o hunter.io o algo así y validarlos!
- administrador, root, prueba, contacto (pruebe los predeterminados para el examen)
```
python3 oh365userfinder.py -r emails.txt -w valid.txt -t 30
```
-Posibilidad de utilizar https://github.com/nyxgeek/onedrive_user_enum (Non-lab-tool)

## Automating OSINT Example
```
#!/bin/bash

domain=$1
RED="\033[1;31m"
RESET="\033[0m"

info_path=$domain/info
subdomain_path=$domain/subdomains
screenshot_path=$domain/screenshots

if [ ! -d "$domain" ];then
    mkdir $domain
fi

if [ ! -d "$info_path" ];then
    mkdir $info_path
fi

if [ ! -d "$subdomain_path" ];then
    mkdir $subdomain_path
fi

if [ ! -d "$screenshot_path" ];then
    mkdir $screenshot_path
fi

echo -e "${RED} [+] Checkin' who it is...${RESET}"
whois $1 > $info_path/whois.txt

echo -e "${RED} [+] Launching subfinder...${RESET}"
subfinder -d $domain > $subdomain_path/found.txt

echo -e "${RED} [+] Running assetfinder...${RESET}"
assetfinder $domain | grep $domain >> $subdomain_path/found.txt

#echo -e "${RED} [+] Running Amass. This could take a while...${RESET}"
#amass enum -d $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Checking what's alive...${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a $subdomain_path/alive.txt

echo -e "${RED} [+] Taking dem screenshotz...${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path/ --no-http
```
