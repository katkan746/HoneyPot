/*
    T-Pot honeypot capture — draft detection rules
    Companion to dionaea/README.md. Style follows yara/wannacry.yara, which was
    assessed in that report but NOT modified.

    Corpus: 55 Dionaea SMB captures (WannaCry) plus 19 Cowrie artefacts
    (RedTail, XorDDoS, Mirai-style probes, one undetermined dropper).
    Observation window for the Dionaea half: 2026-08-17 only. See the report.

    READ BEFORE DEPLOYING
    ---------------------
    No `yara` binary was available on the analysis machine. These rules have
    been hand-checked for syntax but have NEVER been compiled or executed.
    Validate with `yarac` before putting them into production.

    Every match count in the meta blocks below is a PROJECTION derived from
    per-file literal string searches across the corpus, not the result of an
    actual rule run. Every string used has been individually verified present
    in the sample named as its reference.

    No benign corpus was tested against. False-positive rates are therefore
    UNKNOWN, not low. This is the same gap the original wannacry.yara metadata
    admits to; it is repeated here honestly rather than papered over.

    Coverage summary is in indicators/detection-coverage.csv.
*/

import "hash"


/*
   ---------------------------------------------------------------------
   WANNACRY — 55/55 Dionaea SMB captures
   ---------------------------------------------------------------------
   Two rules split by purpose:
     _Loader  detects the dropper shell, including partial captures
     _Payload confirms the ransomware payload archive is actually present
   Run both. _Loader without _Payload means a truncated or stripped capture.
*/

rule WannaCry_Dropper_Loader
{
	meta:
		author = "omar"
		description = "WannaCry outer dropper. Anchors on the launcher.dll/PlayGame export pair, which survives truncated SMB captures that the payload-string rules miss."
		date = "2026-08-17"
		reference_sample = "996c2b2ca30180129c69352a3a3515e4"
		tested_on = "55 Dionaea SMB captures"
		true_positives = "55/55 projected from per-file string presence; rule not executed (no yara binary available)"
		false_positives = "UNKNOWN - no benign PE corpus tested. 'PlayGame' exported from 'launcher.dll' is a documented WannaCry dropper artefact and should be rare in legitimate software, but this is unmeasured."
		note = "Supersedes the mandatory-WNcry@2ol7 approach in yara/wannacry.yara, which misses 7 of these 55 files."
	strings:
		$loader   = "launcher.dll" ascii
		$export   = "PlayGame" ascii
		$drop     = "mssecsvc.exe" ascii
		$droppath = "C:\\%s\\%s" ascii
		$task     = "tasksche.exe" ascii
	condition:
		uint16(0) == 0x5A4D and
		$loader and $export and
		1 of ($drop, $droppath, $task)
}


rule WannaCry_Payload_Complete
{
	meta:
		author = "omar"
		description = "WannaCry with the ransomware payload archive intact. Absence of this rule alongside a WannaCry_Dropper_Loader hit indicates a partial capture."
		date = "2026-08-17"
		reference_sample = "996c2b2ca30180129c69352a3a3515e4"
		tested_on = "55 Dionaea SMB captures"
		true_positives = "48/55 projected. The 7 non-matching files lack WNcry@2ol7, CryptEncrypt and CryptDestroyKey - listed in indicators/wannacry-md5.csv as cluster A2."
		false_positives = "UNKNOWN - no benign PE corpus tested. WNcry@2ol7 is a highly specific ZIP password and unlikely to appear benignly."
	strings:
		$zippw   = "WNcry@2ol7" ascii
		$decrypt = "@WanaDecryptor@" ascii
		$taskdl  = "taskdl.exe" ascii
		$taskse  = "taskse.exe" ascii
		$csp     = "Microsoft Enhanced RSA and AES Cryptographic Provider" ascii
		$crypt   = "CryptEncrypt" ascii
		$destroy = "CryptDestroyKey" ascii
	condition:
		uint16(0) == 0x5A4D and
		$zippw and
		2 of ($decrypt, $taskdl, $taskse, $csp, $crypt, $destroy)
}


rule WannaCry_Killswitch_Domain
{
	meta:
		author = "omar"
		description = "WannaCry kill-switch domain. Informational only - present in just 22 of 55 captures, so this is NOT a reliable family detector on its own."
		date = "2026-08-17"
		reference_sample = "996c2b2ca30180129c69352a3a3515e4"
		tested_on = "55 Dionaea SMB captures"
		true_positives = "22/55 projected"
		false_positives = "UNKNOWN. Will also fire on threat-intel documents, blocklists and reports that merely quote the domain. Do not use standalone."
	strings:
		$domain = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
	condition:
		$domain
}


/*
   ---------------------------------------------------------------------
   REDTAIL — 7 Cowrie artefacts, SSH/SFTP. Not a Dionaea family.
   ---------------------------------------------------------------------
   The two script rules are strong. The binary rules are not - the five ELF
   payloads are UPX-packed with zero plaintext indicators, and none of them
   self-identifies. See the caveats in their meta blocks.
*/

rule RedTail_Installer_Script
{
	meta:
		author = "omar"
		description = "RedTail miner installer shell script. Selects an architecture build, locates a writable non-noexec directory, and launches the payload."
		date = "2026-08-17"
		reference_sample = "1e70b63472772e3f5092ffe9c3573470e73590e6ab6d93fdcede1d368a5fd72d"
		tested_on = "Cowrie downloads; delivered by SFTP as setup.sh"
		true_positives = "1/1 available sample; all strings individually verified present"
		false_positives = "UNKNOWN - no benign shell-script corpus tested. The redtail.* filenames are highly specific; the noexec-enumeration logic is less so."
	strings:
		$arch    = "for a in x86_64 i686 arm8 arm7 riscv" ascii
		$name    = "cat redtail.$ARCH >$FILENAME" ascii
		$cleanup = "rm -rf redtail.*" ascii
		$exec    = "./$FILENAME ssh" ascii
		$noexec1 = "get_noexec_dirs" ascii
		$noexec2 = "findmnt -rn -O noexec -o TARGET" ascii
		$fallback = "redtail" ascii
	condition:
		$fallback and
		2 of ($arch, $name, $cleanup, $exec, $noexec1, $noexec2)
}


rule RedTail_Rival_Miner_Cleanup_Script
{
	meta:
		author = "omar"
		description = "Rival-miner eviction and anti-forensics script paired with the RedTail installer. Disables competing miners and strips loader lines out of all crontabs."
		date = "2026-08-17"
		reference_sample = "3f3a11bafabb1a35db913cfe51995f2e357d049e268860175876ae5a93d23892"
		tested_on = "Cowrie downloads; delivered by SFTP as clean.sh"
		true_positives = "1/1 available sample; all strings individually verified present"
		false_positives = "UNKNOWN. The crontab-filter regex is reused across several unrelated miner families, so this rule may fire on rival campaigns too - arguably desirable, but it means a hit is not proof of RedTail specifically."
	strings:
		$rival1  = "systemctl disable c3pool_miner" ascii
		$rival2  = "systemctl stop bot.service" ascii
		$cron    = "chattr -ia /var/spool/cron/crontabs" ascii
		$anacron = "clean_file /etc/anacrontab" ascii
		$filter  = "bash -i|sh -i|base64 -d" ascii
	condition:
		2 of them
}


rule RedTail_Packed_ELF_Payload_Exact
{
	meta:
		author = "omar"
		description = "Exact-hash detection for the five UPX-packed RedTail architecture builds. Used because the binaries contain no usable plaintext strings."
		date = "2026-08-17"
		reference_sample = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
		tested_on = "5 ELF payloads delivered by SFTP in a single session"
		true_positives = "5/5 by definition, IF the cowrie-assigned filenames are correct. No hashing tool was available to independently recompute them."
		false_positives = "Zero by construction. Also zero resilience - any recompile or repack defeats this entirely."
		note = "Requires yara built with the hash module (OpenSSL). Drop this rule if your build lacks it. Written as an explicit == chain rather than a set membership test, because set syntax for module string returns is version-dependent and could not be compile-checked here."
	condition:
		uint32(0) == 0x464C457F and
		(
			hash.sha256(0, filesize) == "d70f917e35813a7ae323e6b2b539d6dbbfc3a3a6599f1fed93430b14ca08b141" or  // redtail.arm7
			hash.sha256(0, filesize) == "d1cac82f44b54b0fd244a9e4122811e9ae108a197c7a65a20fd2e7552683e68e" or  // redtail.arm8
			hash.sha256(0, filesize) == "8e1a67a5c03b3cd818f046c7a1605afccc0ee5ce437a0d099881f1872b54bc70" or  // redtail.i686
			hash.sha256(0, filesize) == "3f3bf218089d1488617d37f8a5116bb2791eb39ce06a1b5bc9a4cdfe5e94dd39" or  // redtail.riscv
			hash.sha256(0, filesize) == "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"     // redtail.x86_64
		)
}


rule HUNTING_Packed_Stripped_Static_ELF
{
	meta:
		author = "omar"
		description = "HUNTING ONLY - NOT A DETECTION RULE. UPX-packed, section-stripped, statically linked ELF in the size band of the RedTail payload set. Intended for triage queues, never for blocking."
		date = "2026-08-17"
		reference_sample = "f0aa83bbbd2c75e2f71ec16029ee5fcfad59f3a8efa30a500b815f0f6c18d987"
		tested_on = "5 RedTail ELF payloads"
		true_positives = "5/5 projected"
		false_positives = "EXPECTED AND HIGH. This will fire on any UPX-packed ELF, including entirely legitimate ones - UPX is a mainstream compressor. It carries no family specificity whatsoever. Deploying this as a blocking rule would be a mistake."
	strings:
		$upx = "UPX!" ascii
	condition:
		uint32(0) == 0x464C457F and
		#upx >= 2 and
		filesize > 1MB and filesize < 2MB
}


/*
   ---------------------------------------------------------------------
   XORDDOS — 1 Cowrie sample, ELF 32-bit. Not a Dionaea family.
   ---------------------------------------------------------------------
   Strongest rule in this file. The sample is unpacked and the XOR key is the
   family's canonical hardcoded constant.

   NOTE: the C2 field names (denyip=, rmfile=, md5=) are assembled at runtime
   and are NOT contiguous on disk. Verified: a literal search for "denyip="
   returns zero matches. They are deliberately excluded below.
*/

rule XorDDoS_ELF
{
	meta:
		author = "omar"
		description = "XorDDoS Linux DDoS bot. Anchors on the hardcoded BB2FA36AAA9541F0 XOR key plus gcc.sh cron persistence and a spoofed zh-cn User-Agent."
		date = "2026-08-17"
		reference_sample = "6f45c6d9c70d97f695cb7bbef362812a17f8ed4d37dafc342c26c86ed9b43638"
		tested_on = "1 ELF sample uploaded over SSH"
		true_positives = "1/1 available sample; all strings individually verified present with the occurrence counts noted below"
		false_positives = "UNKNOWN - no benign ELF corpus tested. The XOR key is a long, family-specific constant and should be very low risk; the cron and User-Agent strings are corroborating rather than load-bearing."
	strings:
		$xorkey  = "BB2FA36AAA9541F0" ascii        // 6 occurrences
		$cron    = "/etc/cron.hourly/gcc.sh" ascii // 2 occurrences
		$crontab = "*/3 * * * * root /etc/cron.hourly/gcc.sh" ascii
		$ua      = "MSIE 6.0; Windows NT 5.2; SV1; TencentTraveler" ascii
		$lang    = "Accept-Language: zh-cn" ascii
	condition:
		uint32(0) == 0x464C457F and
		(
			#xorkey >= 4 or
			($xorkey and 2 of ($cron, $crontab, $ua, $lang))
		)
}


/*
   ---------------------------------------------------------------------
   MIRAI-STYLE TELNET PROBE — behaviour only, no payload
   ---------------------------------------------------------------------
   The 9 captured artefacts are ZERO BYTES: the bots aborted before
   downloading. There is nothing to scan.

   The rule below is a TEXT-PATTERN rule for scanning captured tty logs, pcap
   payloads and shell-history artefacts. It will never match a binary sample,
   because no binary sample exists.
*/

rule Mirai_Telnet_Writable_Dir_Probe
{
	meta:
		author = "omar"
		description = "Mirai-family writable-directory probe as seen in telnet sessions. FOR LOG AND PCAP SCANNING ONLY - the corresponding honeypot captures are zero bytes, so there is no binary to detect."
		date = "2026-08-17"
		reference_sample = "none - all 9 captured artefacts are 0 bytes"
		tested_on = "9 Cowrie telnet sessions on 2026-08-17"
		true_positives = "9/9 sessions by command-text match in cowrie.json"
		false_positives = "UNKNOWN. Will legitimately fire on honeypot logs, IR notes and threat reports that quote the probe - unavoidable for a log-scanning rule. Scope it to network capture or tty logs."
	strings:
		$probe1  = ">/var/run/.x&&cd /var/run" ascii
		$probe2  = ">/dev/shm/.x&&cd /dev/shm" ascii
		$probe3  = ">/tmp/.x&&cd /tmp" ascii
		$busybox = "/bin/busybox echo -e" ascii
		$menu    = "linuxshell" ascii
	condition:
		2 of ($probe1, $probe2, $probe3) or
		($busybox and $menu)
}


/*
   ---------------------------------------------------------------------
   UNDETERMINED — multi-architecture dropper script
   ---------------------------------------------------------------------
   Lineage consistent with Mirai/Gafgyt loaders, but none of the 12 payloads
   was captured and the script does not self-identify. This detects the
   script, not a family.
*/

rule Multiarch_ELF_Dropper_Script_5_182_210_174
{
	meta:
		author = "omar"
		description = "Shell dropper fetching 12 six-hex-character ELF payloads from 5.182.210.174 and executing each with the argument 'bc'. Family NOT determined - no payload was captured."
		date = "2026-08-17"
		reference_sample = "6aa5054a95d23277df417a5f69cf292e19bc2ef0406bc0c1884935a44e3ce797"
		tested_on = "1 Cowrie download; its delivery session predates the readable log window"
		true_positives = "1/1 available sample"
		false_positives = "UNKNOWN. $host is a campaign-specific address and will go stale when the host rotates; $pattern is generic loader syntax and would be weak alone."
	strings:
		$host    = "http://5.182.210.174/" ascii
		$pattern = "; curl -O http://" ascii
		$chmod   = "chmod 777 " ascii
		$rm      = "rm -rf " ascii
	condition:
		($host and #host >= 4) or
		(3 of ($pattern, $chmod, $rm) and #pattern >= 4)
}
