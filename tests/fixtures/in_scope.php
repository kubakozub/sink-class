<?php
/**
 * Every function here must come back in scope. The verdict is encoded in the
 * name: want_C_* must classify as C, want_I_* as I. A miss here is a finding
 * the tool would have let its user drop.
 */

function want_C_sqli_interpolation() {
    global $wpdb;
    $id = $_GET['id'];
    return $wpdb->get_results( "SELECT * FROM {$wpdb->users} WHERE ID = $id" );
}

function want_C_user_enumeration() {
    $role = $_REQUEST['role'];
    return get_users( array( 'role' => $role, 'fields' => array( 'user_email' ) ) );
}

function want_C_reads_a_secret_option() {
    return get_option( 'acme_remote_api_key' );
}

function want_C_rest_controller_returns_a_query() {
    $args = array( 'post_type' => $_POST['type'], 'post_status' => 'private' );
    return new WP_Query( $args );
}

function want_I_arbitrary_file_write() {
    move_uploaded_file( $_FILES['f']['tmp_name'], WP_CONTENT_DIR . '/' . $_FILES['f']['name'] );
}

function want_I_privilege_escalation() {
    $user = new WP_User( $_POST['uid'] );
    $user->add_role( 'administrator' );
}

function want_I_arbitrary_file_delete() {
    unlink( WP_CONTENT_DIR . '/' . $_REQUEST['path'] );
}

function want_I_option_name_from_request() {
    update_option( $_POST['key'], $_POST['value'] );
}

function want_I_critical_option_by_name() {
    update_option( 'default_role', 'administrator' );
}

function want_I_meta_key_from_request() {
    update_user_meta( $_POST['uid'], $_POST['field'], $_POST['value'] );
}

function want_I_writes_a_user_record() {
    wp_update_user( array( 'ID' => $_POST['uid'], 'user_email' => $_POST['email'] ) );
}
