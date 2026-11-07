<?php
/**
 * The case this tool exists for:
 *
 *     sink-class file examples/acme-booking/inc/telemetry.php
 *
 * Unauthenticated, reachable, and it really does make the site perform work for
 * a stranger. It is still not a report: the only consequence is resource
 * consumption, which is out of scope for the WordPress vulnerability databases
 * and for most programs. A detector that only checks for a missing guard calls
 * this a finding and costs you a rejection.
 */

add_action( 'wp_ajax_nopriv_acme_send_rating', 'acme_send_rating' );

function acme_send_rating() {
    wp_remote_post( 'https://telemetry.example.com/rating', array(
        'body' => array( 'score' => intval( $_POST['score'] ) ),
    ) );
    wp_send_json_success();
}
