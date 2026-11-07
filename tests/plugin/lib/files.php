<?php

function acme_remove_file( $path ) {
    unlink( ABSPATH . $path );
}

function acme_notify( $to ) {
    wp_mail( $to, 'Notification', 'Something happened.' );
}

class Acme_Files {

    public static function is_valid_file_type( $file ) {
        $allowed_types = array( 'png', 'jpg', 'jpeg', 'gif' );
        $ext = strtolower( pathinfo( $file['name'], PATHINFO_EXTENSION ) );
        return in_array( $ext, $allowed_types, true );
    }
}
