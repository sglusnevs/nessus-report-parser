<?php
/**
 * nessus-report-parser -- RouteHandler.php
 * User: Simon Beattie
 * Date: 10/06/2014
 * Time: 15:34
 */

namespace Library;

class Classifier {

    function get($vulnerability) {

        $result = false;

        $rules = array(
          # Malware
          '/Malicious Process/' => array('Malware', "Verdacht auf Malware-Program", "Signatur von einem Windows Process ist einem Malware gleich", "n/a", 'critical'),
          # Antivirus
          '/Anti-Virus/' => array('Antivirus', "Probleme mit Antivirus Program", "System ist von dem Antivirus Program nicht mehr adequat geschützt", "Überprüfen Sie, ob Antivirus Program aktuell gepatcht und mit aktueller Virus-Datenbank versorgt ist", 'critical'),
          # patches management
          '/Silverlight/' => array('Silverlight', "Patch-Management von Drittanwendungen", "Microsoft Silverlight gefunden", "Es wird empfohlen, Silverlight zu deinstallieren oder upzudaten", 'critical'),
          '/(MS\s*\d+|MS KB\s*\d+|KB\s*\d+)|Windows Summary of Missing Patches|MS Security Advisory|Windows Service Pack Out-of-Date/' => array('MS-KB', "Patch-Management von Microsoft Windows", "Windows-System befindet sich nicht auf dem neusten Update-Level", "Es ist empfohlen, fehlende Updates zu installieren", 'critical'),
          '/Microsoft Office Service Pack/' => array('MS-OFFICE', "Patch-Management von Microsoft Office", "Microsoft Office befindet sich nicht auf dem neusten Update-Level", "Es ist empfohlen, fehlende Updates zu installieren", 'critical'),
          '/Microsoft .NET Framework Service Pack Out of Date/' => array('MS-DOTNET', "Patch-Management von Microsoft .NET Framework", "Microsoft .NET Framework befindet sich nicht auf dem neusten Update-Level", "Es ist empfohlen, fehlende Updates zu installieren", 'critical'),
          '/(Oracle|Sun)\s+Java/' => array('Java', "Patch-Management von Drittanwendungen", "Sun/Oracle Java SE/JDK Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),

          '/Unsupported/' => array('Unsupported', "Veraltete Anwendungen", "Anwendungen, die von dem Hersteller nicht mehr unterstützt werden", "Anwendungen sollen upgegradet oder umgetauscht werden", 'critical'),
          '/^Adobe Reader/' => array('AdobeReader', "Patch-Management von Drittanwendungen", "Adobe Reader Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Shockwave/' => array('AdobeShockwave', "Patch-Management von Drittanwendungen", "Adobe Shockwave Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Adobe AIR/' => array('AdobeAir', "Patch-Management von Drittanwendungen", "Adobe AIR Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/^Apache (?!Tomcat).*(Vulnerabilit|Overflow|Execution)/' => array('Apache', "Patch-Management von Drittanwendungen", "Apache Server Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/^Citrix (ICA|Receiver).*(Vulnerabilit|Overflow|Execution)/' => array('CitrixICA', "Patch-Management von Drittanwendungen", "Citrix Client Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Firefox/' => array('Firefox', "Patch-Management von Drittanwendungen", "Firefox Browser Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Flash Player/' => array('AdobeFlash', "Patch-Management von Drittanwendungen", "Flash Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/FLEXnet/' => array('FLEXnet', "Patch-Management von Drittanwendungen", "FLEXnet Connect Update Service ActiveX Control Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Foxit Reader/' => array('FoxitReader', "Patch-Management von Drittanwendungen", "Foxit Reader Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Google Chrome/' => array('GoogleChrome', "Patch-Management von Drittanwendungen", "Google Chrome Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/IrfanView/' => array('IrfanView', "Patch-Management von Drittanwendungen", "IrfanView Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Jenkins/' => array('Jenkins', "Patch-Management von Drittanwendungen", "Jenkins Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/KeyWorks/' => array('KeyWorks', "Patch-Management von Drittanwendungen", "KeyWorks Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/^PHP/' => array('PHP', "Patch-Management von Drittanwendungen", "PHP-Server Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/^OpenSSL/' => array('OpenSSL', "Patch-Management von Drittanwendungen", "OpenSSL Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/VxWorks/' => array('VxWorks WDB Debug', "Patch-Management von Drittanwendungen", "VxWorks WDB Debug Schwachstelle", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/Wireshark/' => array('Wireshark', "Patch-Management von Drittanwendungen", "Wireshark Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/PDF-XChange Viewer/' => array('PDF-XChangeViewer', "Patch-Management von Drittanwendungen", "PDF-XChange Viewer Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/^VLC/' => array('VLCPlayer', "Patch-Management von Drittanwendungen", "VLC Media Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'critical'),
          '/^Adobe PDF Plug-In/' => array('AdobePDFPlugin', "Patch-Management von Drittanwendungen", "Adobe PDF Plug-In Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Apache Tomcat.*(Vulnerabilit|Overflow|Execution)/' => array('Tomcat', "Patch-Management von Drittanwendungen", "Apache Tomcat Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Citrix.*(Vulnerabilit|Overflow|Execution)/' => array('Citrix', "Patch-Management von Drittanwendungen", "Citrix XenApp/XenDesktop Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/CodeMeter.*(Vulnerabilit|Overflow|Execution)/' => array('CodeMeter', "Patch-Management von Drittanwendungen", "CodeMeter Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/FileZilla/' => array('FileZilla', "Patch-Management von Drittanwendungen", "FileZilla Client Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'medium'),
          '/^Macrovision SafeDisc/' => array('MacrovisionSD', "Patch-Management von Drittanwendungen", "Macrovision SafeDisc Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'medium'),
          '/^Samba Badlock/' => array('SambaBadlock', "Patch-Management von Drittanwendungen", "Samba Badlock Schwachstelle", "Es wird empfohlen, Updates zu installieren", 'medium'),
          # default SNMP community names
          '/SNMP Agent Default Community Name \(public\)/' => array('defaultSNMP', "Vorgegebene SNMP Community name (public)", "Es ist möglich, Informationen aus den Systemen auslesen oder sogar ändern", "Vorgegebene Namen sollten geändert werden", 'high'),
          # default/no passwords
          '/Authentication Bypass|SMB Insecurely Configured|Microsoft Windows SMB Registry : Autologon Enabled|LDAP NULL BASE Search Access|SMB NULL Session Authentication/' => array('defaultNoPwd', "Vorkonfigurierte/keine Passwörter", "Zugriff ohne oder mit dem Vorkonfiguriertem Passwort ist möglich", "Vorgegebene Passwörter sollten geändert werden", 'high'),
          # Reboot required
          '/Microsoft Windows Update Reboot Required/' => array('MicrosoftReboot', "Neustart notwendig", "Patches sind zwar installiert, doch ohne Neustart des Systems sind unwirksam", "Starten Die Systeme neu", 'high'),
          # unauth access possible
          '/NFS Shares World Readable|NFS Share User Mountable|Shares Unprivileged Access|Microsoft Windows SMB Share Hosting Office Files/' => array('UnauthPossible', "Ungeschützte Dateien", "Vertraurliche Dateien sind von Unbefugten möglicherweise erreichbar", "Überprüfen Sie, ob wichtige Dateien über NFS/Windows Shares ohne Authentifizierung zugänglich sind", 'high'),
          # leakage
          '/NTP monlist Command Enabled|HTTP TRACE(.*) Methods Allowed|mDNS Detection|Web Server Load Balancer Detection|Disclosure|enumeration|export list|Enumerat/' =>  array('HTTPMethLeakage', "Information Leakage", "Ein Angreifer kann nutzbare Information aus dem Dienst auslesen", 'Dienste sollen umkonfiguriert, ausgeschaltet order mit dem Firewall geschützt werden', 'high'),
          # default services running
          '/Microsoft Windows SMB Registry Remotely Accessible|JBoss JMX Console Unrestricted Access|NFS Server Superfluous|Apache Tomcat(.*) default files|Web Server Unconfigured - Default Install Page Present|Terminal Services Enabled|Windows SMB Shares Access/' =>  array('DefaultServices', "Überflüssige Dienste", "Notwendigkeit einiger Dineste soll überprüft werden (Shares, VNC, Remote Registry usw.)", "Unnötige Dienste sollen ausgeschaltet oder mit dem Firewall geschützt werden", 'high'),
          # DoS/DDos
          '/(DDoS|DoS)/' => array('DoS', "Dienstblockade", 'DoS/DDoS (Angreifer kann das System für Anwender unzugänglich machen)', "Anfällige Dienste sollen ausgeschaltet oder umkonfiguriert werden", 'medium'),
          # Crypto ///
          '/NTLMv1 Authentication Enabled|Unencrypted|Telnet Server|Cleartext|Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness|SMB Signing Disabled|Weak Algorithms|Encryption|TLS|SSH|SSL|Terminal Services Doesn\'t Use Network Level Authentication|HSTS Missing From HTTPS Server/' =>  array('Crypto', "Verschlüsselung", "Veraltete oder keine Verschlüsselung", "Anwendungen sollen umkonfiguriert oder ausgetauscht werden", 'medium'),
          # cached passwords
          '/Microsoft Windows SMB Registry(.*) Password Weakness|IBM iSeries Cached Passwords|Password Hash Disclosure/' => array('MicrosoftSMS', "Unsichere Passwörter-Caching", "Systeme cachen Passswörter im Arbeitsspeicher, wo die dem Angreifer zur Verfügung stehen", "Systeme sollen unkonfiguriert oder upgegradet werden", 'low'),
          # mp3 fies found
          '/Microsoft Windows SMB Share Hosting Possibly Copyrighted Material/' => array('Copyright', "Urheberrecht", "Es ist möglich, dass Shares bestimmte Dateien (wie mp3, .ogg, .mpg, .avi) enthalten, die unter dem Urheberrechtsschutz stehen", "Überprüfen Sie Shares und Dateien", 'low'),
          # further checks needed
          '/Additional DNS Hostnames|Non-standard Port|Insecure Windows Service Permissions|Reputation of Windows Executables: Unknown Process|RIP-2 Poisoning Routing Table Modification|Web Server No 404 Error Code Check|Open Port Re-check/' => array('ChecksNeeded', "Auffälligkeiten", 'Es besteht Verdacht auf bestimmte Schwachstellen, die aber auch "false positives" sein können', 'Bitte anfällige Systeme mithilfe von dem vollständigen Bericht genau auswerten', 'low'),
        );

        $notFound =  array('Uncategorized', "Andere", 'Andere Schwachstellen', 'Verschiedene Schwachstellen ohne Kategorie', 'medium', 10000);

        $order = 0;

        foreach ($rules as $rule_preg => $rule_data ) {

            $order++;

            $cnt = count($rule_data);

            if ($cnt != 5) {

                $msg = "Vulnerability Classification Rule False Parameter Count (must be 5, found $cnt:<pre>". print_r($rule_data);

                die ($msg);
            }

            if (preg_match($rule_preg, $vulnerability)) {

                $rule_data[5] = $order;

                /*
                if (preg_match('/public/', $vulnerability)) {

                     error_log ("Found category for '$vulnerability' (". $rule_data[0] . ")");
                }
                */

                return $rule_data;
            }
        }

        return $notFound;
    }
}
