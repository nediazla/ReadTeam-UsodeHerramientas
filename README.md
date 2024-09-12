# Hoja de trucos para trabajar en Red Team
Hoja de trucos de pentesting/RedTeaming con todos los comandos y técnicas que aprendí durante mi proceso de aprendizaje. La mantendré actualizada. Si tienes alguna recomendación de cursos o enlaces o tienes alguna pregunta, no dudes en enviarme un mensaje privado en Discord.

## Index
* [General](#General)
  * [Coding](coding/readme.md)
  * [Open Source Intelligence](OSINT.md)
  * [Python Dependancies](python_dependancies.md)
  * [Windows System Security](windows_security.md)
  * [Hashcracking](hashcracking.md)
* [Infrastructure](infrastructure/readme.md)
  * [Buffer overflow](infrastructure/bufferoverflow.md)
  * [Enumeration](infrastructure/enumeration.md)
  * [Exploitation](infrastructure/exploitation.md)
  * [Privilege Escalation Windows](infrastructure/privesc_windows.md)
  * [Privilege Escalation Linux](infrastructure/privesc_linux.md)
  * [Post Exploitation](infrastructure/post_exploitation.md)
  * [Pivoting](infrastructure/pivoting.md)
* [Windows AD](windows-ad/readme.md)
  * [Relaying](windows-ad/relaying.md)
  * [Initial Access](windows-ad/Initial-Access.md)
  * [Host Reconnaissance](windows-ad/Host-Reconnaissance.md)
  * [Host Persistence](windows-ad/Host-Persistence.md)
  * [Evasion](windows-ad/Evasion.md)
  * [Local privilege escalation](infrastructure/privesc_windows.md)
  * [Post-Exploitation](windows-ad/Post-Exploitation.md)
  * [Lateral Movement](windows-ad/Lateral-Movement.md)
  * [Domain Enumeration](windows-ad/Domain-Enumeration.md) 
  * [Domain Privilege Escalation](windows-ad/Domain-Privilege-Escalation.md)
  * [Domain Persistence](windows-ad/Domain-Persistence.md)
* [Cloud](cloud/readme.md)
  * [Recon \ OSINT](cloud/recon.md)
  * [Initial access attacks](cloud/initial-access-attacks.md)
  * [Cloud services](cloud/readme.md)
    * [Azure](cloud/azure/readme.md)
    * [Amazon Web Services](cloud/aws/readme.md)
    * [Google Cloud Platform](cloud/gc/readme.md)
* [C2 Frameworks]()
  * [Cobalt Strike](cobalt-strike.md)
  * [Covenant](covenant.md)
  * [Metasploit](metasploit.md)

# RedTeaming General
- Definición de Red Teaming:
> Red Teaming es el proceso de usar tácticas, técnicas y procedimientos (TTPs) para emular una amenaza del mundo real, con el objetivo de medir la efectividad de las personas, los procesos y las tecnologías utilizadas para defender un entorno.
- OPSEC (Seguridad de Operaciones) es un proceso que identifica información crítica para determinar si las acciones pueden ser observadas por la inteligencia enemiga, determina si la información obtenida por los adversarios podría interpretarse como útil para ellos y luego ejecuta medidas seleccionadas que eliminan o reducen la explotación adversaria de la información crítica. Generalmente se usa para describir la "facilidad" con la que las acciones pueden ser observadas por la inteligencia "enemiga".

# Varios
#### Simulación de exfiltración de datos
- https://github.com/FortyNorthSecurity/Egress-Assess

#### Dependencias del administrador de paquetes NuGet
- Open Tools --> NuGet Package Manager --> Package Manager Settings --> Package Sources
- Agregar una fuente. Nombre `nuget.org` y Fuente `https://api.nuget.org/v3/index.json`

#### Bloqueos de red AV/EDR para listas de denegación
- https://github.com/her0ness/av-edr-urls/blob/main/AV-EDR-Netblocks