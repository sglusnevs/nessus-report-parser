-- MySQL dump 10.14  Distrib 5.5.47-MariaDB, for Linux (x86_64)
--
-- Host: localhost    Database: reports
-- ------------------------------------------------------
-- Server version	5.5.47-MariaDB

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `categories`
--

DROP TABLE IF EXISTS `categories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `categories` (
  `categories_id` int(11) NOT NULL AUTO_INCREMENT,
  `categories_public_id` char(16) DEFAULT NULL,
  `severity` enum('info','low','medium','high','critical') DEFAULT NULL,
  `categories_title_main` varchar(255) DEFAULT NULL,
  `categories_subtitle_main` varchar(255) DEFAULT NULL,
  `categories_solution_main` varchar(255) DEFAULT NULL,
  `sort_order` int(11) DEFAULT NULL,
  PRIMARY KEY (`categories_id`),
  UNIQUE KEY `categories_public_id` (`categories_public_id`)
) ENGINE=InnoDB AUTO_INCREMENT=209473 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `host_vuln_link`
--

DROP TABLE IF EXISTS `host_vuln_link`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `host_vuln_link` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `report_id` int(11) DEFAULT NULL,
  `host_id` int(11) DEFAULT NULL,
  `plugin_id` int(11) DEFAULT NULL,
  `port` int(11) DEFAULT NULL,
  `protocol` varchar(32) DEFAULT NULL,
  `service` varchar(32) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `report_id` (`report_id`,`plugin_id`,`host_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1265068 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hosts`
--

DROP TABLE IF EXISTS `hosts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `hosts` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `host_name` varchar(255) DEFAULT NULL,
  `report_id` int(11) DEFAULT NULL,
  `system_type` varchar(64) DEFAULT NULL,
  `operating_system` varchar(255) DEFAULT NULL,
  `host_ip` varchar(30) DEFAULT NULL,
  `host_fqdn` varchar(64) DEFAULT NULL,
  `netbios_name` varchar(64) DEFAULT NULL,
  `mac_address` varchar(255) DEFAULT NULL,
  `credentialed_scan` char(7) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5766 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `ignored`
--

DROP TABLE IF EXISTS `ignored`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ignored` (
  `plugin_id` int(11) unsigned DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  KEY `plugin_id` (`plugin_id`,`user_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `reports`
--

DROP TABLE IF EXISTS `reports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reports` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `report_name` varchar(255) DEFAULT NULL,
  `created` datetime DEFAULT NULL,
  `total_hosts` int(11) DEFAULT NULL,
  `completed_hosts` int(11) DEFAULT NULL,
  `userId` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=100 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `severities`
--

DROP TABLE IF EXISTS `severities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `severities` (
  `plugin_id` int(11) unsigned DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  `severity` tinyint(2) DEFAULT NULL,
  KEY `plugin_id` (`plugin_id`,`user_id`),
  KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL DEFAULT '',
  `password` varchar(255) NOT NULL DEFAULT '',
  `privilege` int(11) NOT NULL DEFAULT '0',
  `name` varchar(255) DEFAULT NULL,
  `pass_length` int(11) DEFAULT NULL,
  `last_updated` datetime DEFAULT NULL,
  `severity` float DEFAULT '4',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `vulnerabilities`
--

DROP TABLE IF EXISTS `vulnerabilities`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `vulnerabilities` (
  `pluginID` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `vulnerability` varchar(255) DEFAULT NULL,
  `svc_name` varchar(30) DEFAULT NULL,
  `severity` float DEFAULT NULL,
  `pluginFamily` varchar(255) DEFAULT NULL,
  `description` text,
  `cve` text,
  `risk_factor` text,
  `see_also` text,
  `solution` text,
  `synopsis` text,
  `randomstormed` int(11) DEFAULT '0',
  `categories_public_id` char(16) DEFAULT NULL,
  `cvss_base_score` float DEFAULT NULL,
  `cvss_temporal_score` float DEFAULT NULL,
  PRIMARY KEY (`pluginID`),
  KEY `vulnerability` (`vulnerability`),
  KEY `pluginID` (`pluginID`,`severity`)
) ENGINE=InnoDB AUTO_INCREMENT=90543 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2016-04-29  9:15:43
