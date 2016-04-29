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
          # patches management
          '/Silverlight/' => array('Silverlight', "Patch-Management von Drittanwendungen", "Microsoft Silverlight gefunden", "Es wird empfohlen, Silverlight zu deinstallieren oder upzudaten", 'high'),
          '/(MS\d+|MS KB\d+)|Windows Summary of Missing Patches|MS Security Advisory/' => array('MS-KB', "Patch-Management von Microsoft Windows", "Windows-System befindet sich nicht auf dem neusten Update-Level", "Es ist empfohlen, fehlende Updates zu installieren (für die komplette Liste bitte )", 'high'),
          '/(Oracle|Sun)\s+Java/' => array('Java', "Patch-Management von Drittanwendungen", "Sun/Oracle Java SE/JDK Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),

          '/Unsupported/' => array('Unsupported', "Veraltete Anwendungen", "Anwendungen, die von dem Hersteller nicht mehr unterstützt werden", "Anwendungen sollen upgegradet oder umgetauscht werden", 'high'),
          '/^Adobe Reader/' => array('AdobeReader', "Patch-Management von Drittanwendungen", "Adobe Reader Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 50),
          '/Shockwave/' => array('AdobeShockwave', "Patch-Management von Drittanwendungen", "Adobe Shockwave Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/^Apache (?!Tomcat).*(Vulnerabilit|Overflow|Execution)/' => array('Apache', "Patch-Management von Drittanwendungen", "Apache Server Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Apache Tomcat.*(Vulnerabilit|Overflow|Execution)/' => array('Tomcat', "Patch-Management von Drittanwendungen", "Apache Tomcat Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/^Citrix (ICA|Receiver).*(Vulnerabilit|Overflow|Execution)/' => array('CitrixICA', "Patch-Management von Drittanwendungen", "Citrix Client Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Citrix.*(Vulnerabilit|Overflow|Execution)/' => array('Citrix', "Patch-Management von Drittanwendungen", "Citrix XenApp/XenDesktop Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/CodeMeter.*(Vulnerabilit|Overflow|Execution)/' => array('CodeMeter', "Patch-Management von Drittanwendungen", "CodeMeter Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/FileZilla/' => array('FileZilla', "Patch-Management von Drittanwendungen", "FileZilla Client Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Firefox/' => array('Firefox', "Patch-Management von Drittanwendungen", "Firefox Browser Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Flash Player/' => array('AdobeFlash', "Patch-Management von Drittanwendungen", "Flash Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Adobe AIR/' => array('AdobeAir', "Patch-Management von Drittanwendungen", "Adobe AIR Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/FLEXnet/' => array('FLEXnet', "Patch-Management von Drittanwendungen", "FLEXnet Connect Update Service ActiveX Control Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Foxit Reader/' => array('FoxitReader', "Patch-Management von Drittanwendungen", "Foxit Reader Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Google Chrome/' => array('GoogleChrome', "Patch-Management von Drittanwendungen", "Google Chrome Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/IrfanView/' => array('IrfanView', "Patch-Management von Drittanwendungen", "IrfanView Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Jenkins/' => array('Jenkins', "Patch-Management von Drittanwendungen", "Jenkins Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/KeyWorks/' => array('KeyWorks', "Patch-Management von Drittanwendungen", "KeyWorks Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/^PHP/' => array('PHP', "Patch-Management von Drittanwendungen", "PHP-Server Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/^OpenSSL/' => array('OpenSSL', "Patch-Management von Drittanwendungen", "OpenSSL Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/^Samba Badlock/' => array('SambaBadlock', "Patch-Management von Drittanwendungen", "Samba Badlock Schwachstelle", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/VxWorks/' => array('VxWorks WDB Debug', "Patch-Management von Drittanwendungen", "VxWorks WDB Debug Schwachstelle", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/Wireshark/' => array('Wireshark', "Patch-Management von Drittanwendungen", "Wireshark Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/PDF-XChange Viewer/' => array('PDF-XChangeViewer', "Patch-Management von Drittanwendungen", "PDF-XChange Viewer Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          '/^VLC/' => array('VLCPlayer', "Patch-Management von Drittanwendungen", "VLC Media Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high'),
          # leakage
          '/HTTP TRACE(.*) Methods Allowed|Information Disclosure|enumeration|export list|Enumerate/' =>  array('HTTPMethLeakage', "Information Leakage", "Ein Angreifer kann nutzbare Information aus dem Dienst auslesen", 'Dienste sollen umkonfiguriert, ausgeschaltet order mit dem Firewall geschützt werden', 'medium'),
          # default passwords/SNMP community names
          '//' => array('MicrosoftSMS', "Unsichere Passwörter-Caching", "Systeme cachen Passswörter im Arbeitsspeicher, wo die dem Angreifer zur Verfügung stehen", "Systeme sollen unkonfiguriert oder upgegradet werden", 'middle'),
          # Reboot required
          '/Microsoft Windows Update Reboot Required/' => array('MicrosoftReboot', "Neustart notwendig", "Patches sind zwar installiert, doch ohne Neustart des Systems sind unwirksam", "Starten Die Systeme neu", 'hoch'),
          # cached passwords
          '/Microsoft Windows SMB Registry(.*) Password Weakness|IBM iSeries Cached Passwords|Password Hash Disclosure/' => array('MicrosoftSMS', "Unsichere Passwörter-Caching", "Systeme cachen Passswörter im Arbeitsspeicher, wo die dem Angreifer zur Verfügung stehen", "Systeme sollen unkonfiguriert oder upgegradet werden", 'middle'),
          # Crypto ///
          '/Unencrypted|Telnet Server|Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness|SMB Signing Disabled|Weak Algorithms|Encryption|TLS|SSH|SSL|Terminal Services Doesn\'t Use Network Level Authentication|HSTS Missing From HTTPS Server/' =>  array('Crypto', "Verschlüsselung", "Veraltete oder keine Verschlüsselung", "Sensible Daten werden mit dieser Anwendung nicht mehr adequat geschützt. Solche anwendungen sollen umkonfiguriert, upgegradet oder ausgetauscht werden", 'medium'),
          # default services running
          '/Microsoft Windows SMB Registry Remotely Accessible|JBoss JMX Console Unrestricted Access|NFS Server Superfluous|Apache Tomcat(.*) default files|Web Server Unconfigured - Default Install Page Present|Terminal Services Enabled|Windows SMB Shares Access/' =>  array('DefaultServices', "Überflüssige Dienste", "Sämtliche Dienste, die Zugriff aus dem Netzwerk erlauben (Web-Server, Windows Shares, VNC, Terminal Services, Remote Registry), sollen überprüft werden, ob diese Dienste tatsächlich notwendig sind", "Unnötige Dienste sollen ausgeschaltet oder mit dem Firewall geschützt werden", 'middle'),
          # unauth access possible
          '/NFS Shares World Readable|Microsoft Windows SMB Share Hosting Office Files/' => array('UnauthPossible', "Ungeschützte Dateien", "Es ist möglich, dass vertraurliche Dateien von allen erreichbar sind", "Überprüfen Sie, ob wichtige Dateien über NFS/Windows Shares ohne Authentifizierung zugänglich sind", 'high'),
          # mp3 fies found
          '/Microsoft Windows SMB Share Hosting Possibly Copyrighted Material/' => array('Copyright', "Urheberrecht", "Es ist möglich, dass Shares bestimmte Dateien (wie mp3, .ogg, .mpg, .avi) enthalten, die unter dem Urheberrechtsschutz stehen", "Überprüfen Sie Shares und Dateien", 'low'),
          # DoS/DDos
          '/(DDoS|DoS)/' => array('DoS', "Dienstblockade", 'Ein Angreifer kann das System für die anderen Anwender unzugänglich machen', "Anfällige Dienste sollen ausgeschaltet oder umkonfiguriert werden", 'middle'),
          # further checks needed
          '/Additional DNS Hostnames|Insecure Windows Service Permissions|Reputation of Windows Executables: Unknown Process|RIP-2 Poisoning Routing Table Modification|Web Server No 404 Error Code Check|Open Port Re-check/' => array('ChecksNeeded', "Auffälligkeiten", 'Es besteht Verdacht auf bestimmte Schwachstellen, die aber auch "false positives" sein können', 'Bitte anfällige Systeme mithilfe von dem vollständigen Bericht genau auswerten', 'low'),
        );

        $notFound =  array('Uncategorized', "Nicht kategorisiert", 'Schwachstelle ohne Kategorie', 'Diese Schwachstelle ist noch nicht kategorisiert', 'info');

        $order = 0;

        foreach ($rules as $rule_preg => $rule_data ) {

            $order++;

            if (preg_match($rule_preg, $vulnerability)) {

                $rule_data[5] = $order;

                return $rule_data;
            }
        }

        return $notFound;
    }
}
