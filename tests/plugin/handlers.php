<?php
/**
 * The handler never touches a sink. Everything it reaches is one call away, in
 * another file, which is the normal shape of plugin code and the reason this
 * tool follows callees at all. Classified without --root, every function here
 * honestly reports that it sees nothing.
 */

function want_I_sink_one_hop_down() {
    $path = $_REQUEST['file'];
    acme_remove_file( $path );
}

function want_A_drain_one_hop_down() {
    acme_notify( $_POST['to'] );
}

function want_A_allowlist_in_a_static_delegate() {
    if ( ! Acme_Files::is_valid_file_type( $_FILES['f'] ) ) {
        return false;
    }
    return media_handle_upload( 'f', 0 );
}
