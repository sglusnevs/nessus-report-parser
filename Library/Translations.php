<?php
/**
 * nessus-report-parser -- RouteHandler.php
 * User: Simon Beattie
 * Date: 10/06/2014
 * Time: 15:34
 */

class NLS {

    function get($arg_const) {

        $result = $arg_const;


        switch ($arg_const) {

            case 'true': $result = 'Ja'; break;
            case 'false': $result = 'Nein'; break;
            case 'low': $result = 'Niedrig'; break;
            case 'middle': $result = 'Mittel'; break;
            case 'high': $result = 'Hoch'; break;
            case 'ip_long': $result = 'IP-Longwert'; break;
            case 'cvss_score_sum': $result = 'CVSS gesamt'; break;
            case 'cvss_score_max': $result = 'CVSS max.'; break;
            case 'host_ip': $result = 'Host-IP'; break;
            case 'host_fqdn': $result = 'Host-FQDN'; break;
            case 'credentialed_scan': $result = 'Scan mit Zugangsdaten?'; break;
            case 'sys_type': $result = 'System-Typ'; break;
            case 'operating_system': $result = 'Betriebssystem'; break;
            case 'netbios_name': $result = 'NetBios-Name'; break;
            case 'mac_address': $result = 'MAC-Adresse'; break;

            case 'report_type_base': $result = 'Bericht nach CVSS-Basiswert'; break;
            case 'report_type_temporal': $result = 'Bericht nach CVSS-Temporalwert'; break;

        }

        return $result;
    }
}

