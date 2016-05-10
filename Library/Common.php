<?php
/**
 * nessus-bulk-parser -- Common.php
 * User: Sergejs Glusnevs
 * Date: 10/05/2016
 * Time: 12:38
 */

function ipLpad($ip) {

    $result = array();

    // roughly check if this is a valid IP (IPv4 or 6)

    if (!preg_match('/([.:])/', $ip, $matches)) {

        return $ip;
    }

    $delim = $matches[0];  // should be either ':' or '.'

    foreach (explode($delim, $ip) as $octet) {

        // pad only digits

        if (preg_match('/^\d+$/', $octet)) {

            $result[] = str_pad($octet, 3, '0', STR_PAD_LEFT);
        }
    }

    // expect minimum lenght as 3 octets

    if (count($result) >= 4) {

        return join($delim, $result);

    } else {

        return $ip;
    }
}

function ipUnpad($ip) {

    $result = array();

    // roughly check if this is a valid IP (IPv4 or 6)

    if (!preg_match('/([.:])/', $ip, $matches)) {

        return $ip;
    }

    $delim = $matches[0];  // should be either ':' or '.'

    foreach (explode($delim, $ip) as $octet) {

        // unpad only digits

        $result[] = preg_replace('/^0+(\d+)/', '$1', $octet);
    }

    // expect minimum lenght as 3 octets

    if (count($result) >= 4) {

        return join($delim, $result);

    } else {

        return $ip;
    }
}
