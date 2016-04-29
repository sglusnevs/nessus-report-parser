nessus-report-parser
====================

Parser and report generation for Nessus and OpenDLP XML reports

REQUIREMENTS:

    apache2
    PHP 5.4+
    php5-mysql
    mysql-server

INSTALLATION:

    Create web directory (change my name for your username):
        mkdir -p /Users/simonbeattie/www
        cd /Users/simonbeattie/www

    Clone the repository:
        git clone https://github.com/simonbt/nessus-report-parser.git

    Create MYSQL Database
        mysql -u root -p reports < Database/mysql_schema.sql

        Setup privileges for another user on the reports database

    Configure System
        edit config.php with Database authentication details

    Add host line within hosts file:
        sudo nano /etc/hosts
        ADD:

            127.0.0.1  reports.local

    Edit the Apache Configuration:
        sudo nano /private/etc/apache2/httpd.conf
        ADD (right at the top of the file):

                NameVirtualHost *:80
                <VirtualHost *:80>
                  ServerName reports.local
                  ServerAdmin simon.beattie@randomstorm.com
                  DocumentRoot "/Users/simonbeattie/www/nessus-report-parser/"

                  <Directory "/Users/simonbeattie/www/nessus-report-parser/">
                    Options Indexes FollowSymLinks MultiViews
                    AllowOverride All
                    Order allow,deny
                    allow from 127.0.0.1
                  </Directory>
                ErrorLog "/private/var/log/apache2/reports-vhost.log"
                LogLevel warn
              </VirtualHost>

        UNCOMMENT:

            #LoadModule php5_module libexec/apache2/libphp5.so

        AND

            #LoadModule rewrite_module libexec/apache2/mod_rewrite.so

    Restart Apache
        sudo apachectl restart

    Completed:
        You should now be able to navigate to the system: http://reports.local
        Default username and password is simon.beattie@randomstorm.com:pa55word

UPDATING:

    Simply run ./update to pull all the latest changes.

UPDATES:

    16th April 2014:
        Changed storage engine from MySQL to SQLite3

    4th June 2014:
        Added PCI report output

    9th June 2014:
        File Management
            Added the ability to upload reports
                You can currently upload any sort of file
            Added the ability to import reports
                This imports into the database through the interface (exactly the same as if you were to use the import.php script)
            Added the ability to delete reports
                Simply removed the uploaded reports (doesn’t yet remove anything from the database)
            Added the ability to merge report
                This uses a modified version of the python script you all use anyway. I’ve tested merging up to 4 reports at once.
            Interface Updates
                A number of changes to how information is displayed, and generally CSSing

    10th June 2014:
            Limitation to file upload type (.xml & .nessus) -- REMOVED DUE TO SAFARI BUG
            Added 900row limit for vulnerability report tables due to pages bug
            Report output for OpenDLP reports
            Added file management functionality for OpenDLP
            Added OpenDLP reports list

    11th June 2014:
            Complete rewrite of a large portion of the application
            Integrated slim micro framework
            Removed all reliance on Curl
            Nessus report importing fully available through interface
            Moved all reports onto view templates and implemented render() method

    12th June 2014:
            Refactored application for a server model
            Added authentication
            Added user administration (add, remove, change)
            Added user specific report views
            Separated user uploads
            Major interface overhaul
            Moved all templates into view folders
            Added site wide headers and footers
            Removed all CSS loading screens
            Moved back to MySQL

    13th June 2014:
            Added validation for OpenDLP and Nessus XML uploads

    20th January 2015:
            Changed Internal and External output tables to reflect report changes
            Added TCP/UDP Open ports report

TO-DO:

        Limitation to file upload sizes
        .xls output for all vulnerabilities
        Template download / storage
        Reinstate the ability to change severity filter through interface
        Move footer to float at the bottom!
        CSS menu drop downs to fit correctly
        Implement privilege levels
        Add user management page
        Add custom report creation
