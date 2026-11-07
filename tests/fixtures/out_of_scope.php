<?php
/**
 * Every function here must come back OUT OF SCOPE. These matter more than the
 * in-scope half: a classifier that calls correct code a vulnerability costs its
 * user a rejected report, and rejected reports are what this tool exists to
 * prevent.
 *
 * want_A_* must classify as A, want_P_* as P.
 */

function want_A_mail_flood() {
    foreach ( $GLOBALS['list'] as $address ) {
        wp_mail( $address, $_POST['subject'], $_POST['message'] );
    }
}

function want_A_unmetered_outbound_call() {
    return wp_remote_post( 'https://api.example.com/v1/complete', array(
        'body' => $_POST['prompt'],
    ) );
}

function want_A_upload_behind_an_extension_allowlist() {
    $allowed_file_types = array( 'png', 'jpg', 'jpeg', 'gif' );
    $ext = strtolower( pathinfo( $_FILES['file']['name'], PATHINFO_EXTENSION ) );
    if ( ! in_array( $ext, $allowed_file_types, true ) ) {
        return array( 'code' => 502 );
    }
    return media_handle_upload( 'file', 0 );
}

function want_A_upload_validated_by_content() {
    if ( ! getimagesize( $_FILES['file']['tmp_name'] ) ) {
        return false;
    }
    return wp_handle_upload( $_FILES['file'], array( 'test_form' => false ) );
}

function want_A_self_scoped_row_next_to_a_drain() {
    global $wpdb;
    $wpdb->insert( $wpdb->prefix . 'acme_submissions', array( 'body' => $_POST['body'] ) );
    set_transient( 'acme_last_submission', time(), 300 );
}

function want_P_password_reset() {
    return retrieve_password( $_POST['user_login'] );
}

function want_P_login() {
    return wp_signon( array(
        'user_login'    => $_POST['log'],
        'user_password' => $_POST['pwd'],
    ), is_ssl() );
}

function want_P_reset_key_check() {
    return check_password_reset_key( $_GET['key'], $_GET['login'] );
}
