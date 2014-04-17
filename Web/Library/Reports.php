<?php
/**
 * ReportGenerator -- Reports.php
 * User: Simon Beattie
 * Date: 14/04/2014
 * Time: 12:27
 */

namespace Library;


class Reports extends \Library\WebAbstract
{

    function listReports()
    { // List all reports that have been imported into the system

        $reports = array();

        $listReportQuery = $this->getPdo()->prepare('SELECT * FROM reports');
        $listReportQuery->execute();
        $reportList = $listReportQuery->fetchAll(\PDO::FETCH_ASSOC);

        foreach ($reportList as $report) {
            array_push($reports, array('id'          => $report['id'],
                                       'report_name' => $report['report_name'],
                                       'created'     => $report['created']));

        }

        return $reports;
    }

    function getAllData($reportID, $severity)
    { // Returns all data filtered by severity and report ID
        $getHostIDs = $this->getPdo()->prepare('SELECT DISTINCT host_id FROM host_vuln_link WHERE report_id=?');
        $getHostName = $this->getPdo()->prepare('SELECT host_name, operating_system FROM hosts WHERE id=?');
        $getVulnerabilites = $this->getPDO()->prepare('SELECT DISTINCT plugin_id FROM host_vuln_link WHERE report_id=? AND host_id=?');
        $getDetails = $this->getPdo()->prepare('SELECT vulnerability FROM vulnerabilities WHERE pluginID = ?');

        $getHostIDs->execute(array($reportID));
        $hosts = $getHostIDs->fetchall(\PDO::FETCH_ASSOC);
        if (!$hosts) {
            die('Sorry, we couldn\'t get the host ID list: ' . $getHostIDs->errorInfo()[2] . PHP_EOL);
        }

        foreach ($hosts as $key => $host)
        {
            $getHostName->execute(array($host['host_id']));
            $hostName = $getHostName->fetchall(\PDO::FETCH_ASSOC);
            $hosts[$key]['hostname'] = $hostName[0]['host_name'];
            $hosts[$key]['OS'] = $hostName[0]['operating_system'];

            $getVulnerabilites->execute(array($reportID, $host['host_id']));
            $vulnerabilites = $getVulnerabilites->fetchall(\PDO::FETCH_COLUMN);

            foreach ($vulnerabilites as $vulnerability)
            {
                $getDetails->execute(array($vulnerability));
                $details = $getDetails
                return $vulnerability;
            }

            $hosts[$key]['vulnerabilities'] = $vulnerabilites;


            }

        return $hosts;
    }

    function getDetails($reportID, $severity)
    { // Returns all report data for all hosts, filtered by severity and report ID but sorted by vulnerability.

        $returnTable = array();
        $getPluginIDs = $this->getPdo()->prepare('SELECT DISTINCT(plugin_id) as id FROM host_vuln_link WHERE report_id = ?');
        $getHostIDs = $this->getPdo()->prepare('SELECT host_id, port, protocol FROM host_vuln_link WHERE plugin_id =? and report_id =?');
        $getHostName = $this->getPdo()->prepare('SELECT host_name FROM hosts WHERE id=?');
        $getDetails = $this->getPdo()->prepare('SELECT * FROM vulnerabilities WHERE pluginID = ? AND severity >?');


        $getPluginIDs->execute(array($reportID));
        $pluginIDs = $getPluginIDs->fetchAll(\PDO::FETCH_COLUMN);
        if (!$pluginIDs) {
            die('Sorry, we couldn\'t get the plugin ID list: ' . $getPluginIDs->errorInfo()[2] . PHP_EOL);
        }


        foreach ($pluginIDs as $plugin) {

            $getDetails->execute(array($plugin, $severity));
            $details = $getDetails->fetchAll(\PDO::FETCH_ASSOC);
            if (!$details) {
                continue;
            }

            $getHostIDs->execute(array($plugin, $reportID));
            $hostIDs = $getHostIDs->fetchAll(\PDO::FETCH_ASSOC);
            if (!$hostIDs) {
                die('Sorry, we couldn\'t get the hosts list: ' . $getHostIDs->errorInfo()[2] . PHP_EOL);
            }

            foreach ($hostIDs as $i => $id) {
                $getHostName->execute(array($id['host_id']));
                $hostName = $getHostName->fetch(\PDO::FETCH_COLUMN);

                $hostIDs[$i]['host_id'] = $hostName;
            }

            $returnTable[$plugin] = array($details, $hostIDs);

        }

        return $returnTable;
    }
} 