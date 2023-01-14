<?php

require $_SERVER['DOCUMENT_ROOT'] . '/php/app.php';

if (isset($_POST['email'])) {
    $em = clean($_POST['email'], "lo");
    $em = filter_var($em, FILTER_SANITIZE_EMAIL);

    if (!filter_var($em, FILTER_VALIDATE_EMAIL)) {
        // quit if emal validation filter fails
        $ms = "No valid email in post";
        goto end;
    } else {
        $ems = spe($em, 'e');
        $eme = enc($ems, 'e');
        $emh = xhash($eme);

        $uex = ckex(
            // check if email from post exists in db
            $sv,
            $un,
            $pw,
            $db, $sel = 'email',
            $tn, $whr = 'email', $val = $ems
        );

        if (!$uex) {
            //~ Email not in DB -> visitor login request without em in db

            if (!cset('t')) {
                // set visitor trial-cookie if not set yet
                $tc = enc('1', 'e');
                setcookie('t', $tc, dur(60 * 60));
            } else {
                // decode cookie t first
                $tc = enc($_COOKIE['t'], 'd');

                if ($tc > '4') {
                    /* block visitor if time-cookie is above 4,
                    resulting from to many trials to reset pass or log in */
                    $jres = "bk";
                    goto end;
                } else {
                    /* maximum trials not reached:
                    add 1 to trial-cookie and set as cookie */
                    $tc = ($tc + 1);
                    $tc = enc($tc, 'e');
                    setcookie('t', $tc, dur(60 * 60));
                }
            }

            $jres = "no";
            goto end;
        } else {
            //~ Email in DB -> existing user log in request

            $conn = mysqli_connect($sv, $un, $pw, $db);
            if (mysqli_connect_errno()) {
                $ms = 'ERROR: No conn to db "'
                . $db . '"-' . mysqli_connect_error();
                goto end;
            } else {
                /* get user-name, password, unit & trial from db
                where entry is the encoded email from post */
                $res = mysqli_query(
                    $conn, "SELECT user,password,unix,trial FROM "
                    . $tn . " WHERE email='" . $ems . "'"
                );
                $row = mysqli_fetch_array($res, MYSQLI_ASSOC);
                $trial = $row['trial'];
                $unix = $row['unix'];
                $usr = $row['user'];

                // clean, special char & encode password from post
                $pass = clean($_POST['pass'], false);
                $pass = spe($pass, 'e');
                $pass = enc($pass, 'e');

                /* verify if hash from db pass row
                matches the pass entry from input sent as post */
                $pm = vhash($pass, $row['password']);
            }

            if ($pm) {
                //& pass match

                $unm = spe($usr, 'd');
                // save user name cookie for later usage
                setcookie('u', $unm, dur(60 * 60));

                /* save enc email as cookie lg, to be able to xhash &
                compare it later with ulog column in db to see if lgd */
                setcookie('lg', $eme, dur(60 * 60));

                // enter email hashed in db
                mysqli_query(
                    $conn, "UPDATE " . $tn . " SET ulog='"
                    . $emh . "' WHERE email ='" . $ems . "'"
                );

                // reset unix time on log in
                mysqli_query(
                    $conn, "UPDATE " . $tn . " SET unix='"
                    . $nt . "' WHERE email ='" . $ems . "'"
                );

                // reset trial on new log in
                mysqli_query(
                    $conn, "UPDATE " . $tn
                    . " SET trial='0' WHERE email ='" . $ems . "'"
                );

                // delete trial cookie
                if (cset('t')) {
                    delc('t');
                }

                $jres = "lo"; //~ all good > logging
                goto end;
            } else {
                //& password from post, doesn't match the one in db
                $trial++;

                if ($trial > 4 && ($nt - 86400) < $unix) {
                    // block if more than 4 trials in less than 24h
                    $jres = 'rc';
                    goto end;
                }

                if ($trial <= 4 && ($nt - 86400) < $unix) {
                    // add 1 to trial db column if less than 4 trials in 24h
                    mysqli_query($conn, "UPDATE " . $tn
                        . " SET trial='" . $trial
                        . "' WHERE email ='" . $ems . "'");
                }

                if ($trial > 4 && ($nt - 86400) > $unix) {
                    // reset trial in db to 1 after 24h
                    mysqli_query(
                        $conn, "UPDATE " . $tn
                        . " SET trial='1' WHERE email ='" . $ems . "'"
                    );
                }

                // update unix col entry on every trial
                mysqli_query(
                    $conn, "UPDATE " . $tn . " SET unix='"
                    . $nt . "' WHERE email ='" . $ems . "'"
                );

                $jres = "wp";
                goto end;
            }
        }
    }
}

end:

if ($ms) {
    lg($lg, $p, $tm, $ms);
}

if (isset($conn->server_info)) {
    mysqli_close($conn);
}

echo $jres;