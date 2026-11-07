<?php
/**
 * A small, deliberately mixed plugin, so the README's output can be reproduced
 * rather than imagined:
 *
 *     sink-class file examples/acme-booking/inc/ajax.php
 *
 * Both handlers here are worth a report. The handler that is not worth a report
 * lives in telemetry.php, because it is the more interesting case.
 */

add_action( 'wp_ajax_nopriv_acme_save_profile', 'acme_save_profile' );
add_action( 'wp_ajax_nopriv_acme_export_users', 'acme_export_users' );

function acme_save_profile() {
    $uid = intval( $_POST['uid'] );
    update_user_meta( $uid, $_POST['field'], $_POST['value'] );
    wp_send_json_success();
}

function acme_export_users() {
    $rows = get_users( array(
        'role'   => $_REQUEST['role'],
        'fields' => array( 'ID', 'user_email' ),
    ) );
    wp_send_json_success( $rows );
}
