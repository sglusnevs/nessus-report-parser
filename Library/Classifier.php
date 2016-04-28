<?php
/**
 * nessus-report-parser -- RouteHandler.php
 * User: Sergejs Glusnevs
 * Date: 04/29/2014
 * Time: 12:18
 */

class Classifier {

    function classify($vulnrability) {

        $result = '';

        $rules = array(
          # patches management
          '/Silverlight/' => array("Patch-Management von Drittanwendungen", "Microsoft Silverlight gefunden", "Es wird empfohlen, Silverlight zu deinstallieren oder upzudaten", 'high', 10),
          '/(MS\d+|MS,KB\d+)|Windows Summary of Missing Patches|MS Security Advisory/' => array("Patch-Management von Microsoft Windows", "Windows-System befindet sich nicht auf dem neusten Update-Level", "Es ist empfohlen, fehlende Updates zu installieren (für die komplette Liste bitte )", 'high', 20),
          '/(Oracle|Sun)\s+Java/' => array("Patch-Management von Drittanwendungen", "Sun/Oracle Java SE/JDK Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 30),

          'Unsupported' => array("Veraltete Anwendungen", "Anwendungen, die von dem Hersteller nicht mehr unterstützt werden", "Anwendungen sollen upgegradet oder umgetauscht werden", 'high', 40),
          '/^Adobe Reader/' => array("Patch-Management von Drittanwendungen", "Adobe Reader Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 50),
          '/Adobe Shockwave/' => array("Patch-Management von Drittanwendungen", "Adobe Shockwave Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 60),
          '/^Apache (?!Tomcat)/' => array("Patch-Management von Drittanwendungen", "Apache Server Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 70),
          '/Apache Tomcat/' => array("Patch-Management von Drittanwendungen", "Apache Tomcat Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 80),
          '/^Citrix (ICA|Receiver)/' => array("Patch-Management von Drittanwendungen", "Citrix Client Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 90),
          '/Citrix/' => array("Patch-Management von Drittanwendungen", "Citrix XenApp/XenDesktop Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 100),
          '/CodeMeter/' => array("Patch-Management von Drittanwendungen", "CodeMeter Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 1070),
          '/FileZilla/' => array("Patch-Management von Drittanwendungen", "FileZilla Client Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 110),
          '/Firefox/' => array("Patch-Management von Drittanwendungen", "Firefox Browser Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 120),
          '/Adobe Flash Player/' => array("Patch-Management von Drittanwendungen", "Flash Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 130),
          '/FLEXnet/' => array("Patch-Management von Drittanwendungen", "FLEXnet Connect Update Service ActiveX Control Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 140),
          '/Foxit Reader/' => array("Patch-Management von Drittanwendungen", "Foxit Reader Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 150),
          '/Google Chrome/' => array("Patch-Management von Drittanwendungen", "Google Chrome Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 160),
          '/IrfanView/' => array("Patch-Management von Drittanwendungen", "IrfanView Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 170),
          '/KeyWorks/' => array("Patch-Management von Drittanwendungen", "KeyWorks Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 180),
          '/^PHP/' => array("Patch-Management von Drittanwendungen", "PHP-Server Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 190),
          '/^OpenSSL/' => array("Patch-Management von Drittanwendungen", "OpenSSL Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 200),
          '/PDF-XChange Viewer/' => array("Patch-Management von Drittanwendungen", "PDF-XChange Viewer Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 210),
          '/^VLC/' => array("Patch-Management von Drittanwendungen", "VLC Media Player Schwachstellen", "Es wird empfohlen, Updates zu installieren", 'high', 220),
          # leakage
          'HTTP TRACE(.*) Methods Allowed|(FTP|HTTP) +Server|Listener Detection|Disclosure|Version Information|Traceroute Information|Version Information|Service Detection|enumeration|export list|Enumerate|Users Information|User List' =>  array("Information Leakage", "Ein Angreifer kann nutzbare Information aus dem Dienst auslesen", 'Dienste sollen umkonfiguriert, ausgeschaltet order mit dem Firewall geschützt werden', 'medium', 230),
          # default passwords
          'SMB Log In Possible|SNMP Agent Default Community Name \(public\)' =>  array("Vorkonfigurierte Zugangsdaten", "Es ist möglich, sich mit dem Standartbenutzer/Passwort oder sogar ohne Passwort einzuloggen", "Unbenutze Kontos sollen deaktiviert werden, Passwörter müssen geändert werden", 'high', 240),
          # cached passwords
          'Microsoft Windows SMB Registry(.*) Password Weakness|IBM iSeries Cached Passwords|Password Hash Disclosure' => array("Unsichere Passwörter-Caching", "Systeme cachen Passswörter im Arbeitsspeicher, wo die dem Angreifer zur Verfügung stehen", "Systeme sollen unkonfiguriert oder upgegradet werden", 'middle', 250),
          # Crypto ///
          'Telnet Server Detection|Unencrypted Telnet Server|Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness|SMB Signing Disabled|Weak Algorithms|Encryption|TLS|SSH|SSL|Terminal Services Doesn\'t Use Network Level Authentication|HSTS Missing From HTTPS Server' =>  array("Verschlüsselung", "Veraltete oder keine Verschlüsselung", "Sensible Daten werden mit dieser Anwendung nicht mehr adequat geschützt. Solche anwendungen sollen umkonfiguriert, upgegradet oder ausgetauscht werden", 'medium', 260),
          # default services running
          'Microsoft Windows SMB Registry Remotely Accessible|JBoss JMX Console Unrestricted Access|NFS Server Superfluous|Apache Tomcat(.*) default files|Web Server Unconfigured - Default Install Page Present|Terminal Services Enabled|Windows SMB Shares Access' =>  array("Überflüssige Dienste", "Sämtliche Dienste, die Zugriff aus dem Netzwerk erlauben (Web-Server, Windows Shares, VNC, Terminal Services, Remote Registry), sollen überprüft werden, ob diese Dienste tatsächlich notwendig sind", "Unnötige Dienste sollen ausgeschaltet oder mit dem Firewall geschützt werden", 'middle', 270),
          # unauth access possible
          'NFS Shares World Readable|Microsoft Windows SMB Share Hosting Office Files' => array("Ungeschützte Dateien", "Es ist möglich, dass vertraurliche Dateien von allen erreichbar sind", "Überprüfen Sie, ob wichtige Dateien über NFS/Windows Shares ohne Authentifizierung zugänglich sind", 'high', 280),
          # mp3 fies found
          'Microsoft Windows SMB Share Hosting Possibly Copyrighted Material' => array("Urheberrecht", "Es ist möglich, dass Shares bestimmte Dateien (wie mp3, .ogg, .mpg, .avi) enthalten, die unter dem Urheberrechtsschutz stehen", "Überprüfen Sie Shares und Dateien", 'low', 290),
          # DoS/DDos
          'DDoS' => array("Dienstblockade", 'Ein Angreifer kann das System für die anderen Anwender unzugänglich machen', "Anfällige Dienste sollen ausgeschaltet oder umkonfiguriert werden", 'middle', 300),
          # further checks needed
          'Additional DNS Hostnames|Insecure Windows Service Permissions|Reputation of Windows Executables: Unknown Process|RIP-2 Poisoning Routing Table Modification|Web Server No 404 Error Code Check|Open Port Re-check' => array("Auffälligkeiten", 'Es besteht Verdacht auf bestimmte Schwachstellen, die aber auch "false positives" sein können', 'Bitte anfällige Systeme mithilfe von dem vollständigen Bericht genau auswerten', 'low', 1000),
        );

        return $result;
    }

}
