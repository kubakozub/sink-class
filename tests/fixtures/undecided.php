<?php
/**
 * Neither in scope nor out of it. The honest answer is that a human has to look,
 * and a tool that guesses here is worse than one that says so.
 *
 * want_Iq_* must classify as I?, want_none_* as "-".
 */

function want_Iq_cosmetic_option_flag() {
    update_option( 'acme_prompt_seen', true );
    $rating = intval( $_POST['rating'] );
    return $rating;
}

function want_Iq_plugin_table_write() {
    global $wpdb;
    $wpdb->update( $wpdb->prefix . 'acme_counters', array( 'hits' => 1 ), array( 'id' => 7 ) );
}

function want_none_pure_computation() {
    $x = 1;
    $y = $x + 2;
    return $y;
}

function want_none_output_only() {
    echo esc_html( sanitize_text_field( $_POST['label'] ) );
}
