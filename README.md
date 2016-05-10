nessus-parser
====================

This tool is based on the Nessus Report Parser by Simon Beattie (https://github.com/simonbt/nessus-report-parser)

I attempted to modify original version to process Nessus reports, collected from larger environments.

In case if you experience problems trying to import large .nessus files, make sure you have enough RAM -- Python script performing import is pretty resource-intensive.

I recommend a decent VM with at least of couble Gigabytes of RAM.

REQUIREMENTS:

    apache2
    PHP 5.4+
    php5-mysql
    mysql-server

INSTALLATION:

    For Kali Linux:

    # apt-get install php5 apache2 php5-mysql mysql-server git

    # systemctl enable apache2 ;  systemctl start apache2

    # systemctl enable mysql ;  systemctl start mysql

    # cd /var/www/html/

    Clone the repository:

    # git clone https://<USERNAME>@bitbucket.org/seveal/nessus-report-parser.git

    # cd /var/www/html/nessus-report-parser

    Make uploads folder writable:

    # chmod -R a+rwx /var/www/html/nessus-report-parser/Library/uploads/

    Create MYSQL Database

    # mysql -u root -p < Database/mysql_schema.sql

    Create user for reports database

    # echo 'CREATE USER "reports"@"localhost" IDENTIFIED BY "password";' | mysql -u root -p

    # echo 'GRANT ALL PRIVILEGES ON reports.* TO "reports"@"localhost";' | mysql -u root -p

    # echo 'FLUSH PRIVILEGES;' | mysql -u root -p

    Configure System
        edit config.php with Database authentication details

    Add host line within hosts file:
        sudo vi /etc/hosts
        ADD:

            127.0.0.1  reports.local

    Edit the Apache Configuration:
        sudo vi /etc/apache2/sites-available/000-default.conf

        Find string starting with "DocumentRoot" and replace with:

            DocumentRoot /var/www/html/nessus-report-parser


        Add the following lines straight after that:

        <Directory /var/www/html/nessus-report-parser>
            Options Indexes FollowSymLinks MultiViews
            AllowOverride All
        </Directory>


        Enable Apache modules:

        # ln -s /etc/apache2/mods-available/rewrite.load  /etc/apache2/mods-enabled/

        # ln -s /etc/apache2/mods-available/php5.load  /etc/apache2/mods-enabled/

        Set the following in your php.ini: `upload_max_filesize = 2048M´, `post_max_size = 2048M´ to be able to upload huge reports

        # sudo vi /etc/php5/apache2/php.ini


    Restart Apache
        sudo apachectl restart

    Completed:
        You should now be able to navigate to the system: http://reports.local
        Default username and password is adminstvo:pa55word

UPDATING:

    Run to pull all the latest changes:

    # cd /var/www/html/nessus-report-parser

    # git pull



NEW REPORTS:

        1. Add Nessus reports to drop-down in

        views/menus/nessusIndex.phtml

          <option value="report_tag/' . $report['id'] . '">report_name</option>

          2. Add Routes in Routes/reports.php

          3. Add SQL in Library/ReportData.php

          3. Add render into views/reports/<my_report>.phtml

