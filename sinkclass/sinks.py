"""The sink tables, and the case that forced each entry.

Every table here is a claim about impact, not about syntax. A rule earns its
place by naming the mistake it fixes: a sink the previous table could not see,
or a benign call the previous table called a vulnerability. Entries without that
provenance tend to be guesses, and guesses are what make a classifier unusable.
"""

from __future__ import annotations

import re

# ----------------------------------------------------------------- reads

READ = [
    (r'\$wpdb->\s*(get_results|get_row|get_var|get_col)\s*\(', 'wpdb read'),
    (r'\bget_user(meta|_meta|data|s_by|_by)\s*\(', 'user record read'),
    (r'->\s*(user_pass|user_email|user_activation_key)\b', 'credential field'),
    (r'\bfile_get_contents\s*\(|\breadfile\s*\(|\bfread\s*\(', 'file read'),
    (r'\bget_post_meta\s*\(', 'post meta read'),
    (r'\bget_users\s*\(', 'user enumeration'),
    # REST controllers rarely echo. They collect and return, so the first READ
    # table saw nothing: 43 handlers came back "no recognised sink" while
    # returning query results straight to an unauthenticated caller.
    (r'\bget_posts\s*\(|new\s+WP_Query\s*\(', 'post query'),
    (r'\bget_comments\s*\(', 'comment query'),
    (r'\bget_terms\s*\(', 'term query'),
    (r'\bget_(post|page)_by_path\s*\(|\bget_page_by_title\s*\(', 'post lookup'),
    (r'\bget_(site_)?option\s*\(\s*[^\)]{0,60}'
     r'(api[_-]?key|secret|token|password|credential)', 'reads a secret option'),
]

# ----------------------------------------------------------------- writes

# Not every write crosses a privilege boundary. A row recording the caller's own
# submission is the feature working. Overwriting global configuration is a
# finding. The case that forced the tiering: a handler that stored an attachment
# id into the form row the caller had already addressed. Literally a write,
# worth nothing. Without tiers every guestbook plugin looks critical.
#
# For options, the NAME decides the impact. update_option('default_role',
# 'administrator') is privilege escalation. update_option('x_prompt_seen', true)
# hides a UI hint, and an unauthenticated endpoint that writes one is still worth
# nothing. Weigh the name, not the call.

# Endpoints that MUST work without authentication. Measured against a donation
# plugin's route table: three of eight writes flagged for review were login,
# password reset and email verification, and all three have to be reachable by an
# anonymous caller, exactly like core's wp-login.php?action=lostpassword. The
# write a detector sees there is the reset key: the mechanism, not the hole.
# The list is deliberately narrow. Only core functions that defend themselves:
# delivery restricted to the registered address, key validation, password
# validation.
PUBLIC_BY_DESIGN = re.compile(
    r"\b(retrieve_password|wp_signon|wp_authenticate|check_password_reset_key)\s*\("
)

OPTION_CRITICAL = re.compile(
    r"""(update|add)_(site_)?option\s*\(\s*['"]?\s*("""
    r"""users_can_register|default_role|admin_email|new_admin_email|siteurl|home"""
    r"""|wp_user_roles|\w*(api[_-]?key|secret|token|password|passwd|credential)\w*"""
    r"""|active_plugins|template|stylesheet|upload_path|db_version"""
    r""")""", re.I)

# Request-controlled option NAME: update_option($_POST['name'], ...). The caller
# picks which option, so every critical one above is in reach.
OPTION_KEYED = re.compile(
    r"""(update|add)_(site_)?option\s*\(\s*[^'"\)]{0,80}"""
    r"""(\$_(GET|POST|REQUEST)\b|->\s*get_param\s*\()""", re.I)

WRITE_STRONG = [
    (r'\bwp_(update|insert)_user\s*\(', 'user record write'),
    (r'->\s*(add_role|set_role|add_cap|remove_cap)\s*\(', 'role or capability write'),
    (r'\bwp_set_(password|auth_cookie|current_user)\s*\(', 'authentication write'),
    (r'\bwp_(delete|trash)_post\s*\(', 'post delete'),
    (r'\bwp_delete_attachment\s*\(', 'attachment delete'),
    (r'\b(file_put_contents|fwrite|rename|copy|mkdir)\s*\(', 'filesystem write'),
    (r'\bunlink\s*\(', 'file delete'),
    (r'\bmove_uploaded_file\s*\(', 'raw upload move'),
]

# A request-controlled META KEY is the whole game: update_user_meta($id,
# $_POST['k'], ...) reaches wp_capabilities and becomes privilege escalation.
WRITE_KEYED = re.compile(
    r'\b(update|add)_(user|post)_meta\s*\([^;]{0,120}'
    r'(\$_(GET|POST|REQUEST)\b|->\s*get_param\s*\()', re.I | re.S)

WRITE_WEAK = [
    (r'\b(update|add|delete)_(site_)?option\s*\(', 'option write (uncritical name)'),
    (r'\$wpdb->\s*(update|insert|delete|replace)\s*\(', 'plugin table write'),
    (r'\b(update|add|delete)_(user|post)_meta\s*\(', 'meta write'),
    (r'\bwp_(insert|update)_post\s*\(', 'post write'),
]

# ----------------------------------------------------------------- drains

# Resource consumption. Real, provable, and not reportable to a coordinator whose
# scope excludes availability.
DRAIN = [
    (r'\bwp_mail\s*\(|->\s*send\s*\(', 'mail send'),
    (r'\bwp_remote_(post|get|request)\s*\(', 'outbound HTTP (cost)'),
    (r'\bset_transient\s*\(|\bwp_cache_set\s*\(', 'cache write'),
    (r'\bwp_schedule_(single_)?event\s*\(', 'cron schedule'),
    (r'\bmedia_handle_(upload|sideload)\s*\(|\bwp_handle_upload\s*\(', 'mediated upload'),
]

REQ_INPUT = re.compile(
    r'\$_(GET|POST|REQUEST|FILES|COOKIE)\b'
    r'|->\s*get_param\s*\(|->\s*get_json_params\s*\(|->\s*get_file_params\s*\(',
    re.I)

# ----------------------------------------------------------------- uploads

# An extension allowlist turns an upload from "arbitrary file write" into
# "someone filled your disk". That single distinction decides whether an upload
# handler is worth a report.
#
# The first version knew only in_array($ext, ...) and wp_check_filetype(), so it
# called an admin-gated, getimagesize() validated, 'mimes' restricted upload an
# arbitrary file write. Cover the idioms that actually appear in plugin code.
EXT_ALLOWLIST = re.compile(
    r'wp_check_filetype(_and_ext)?\s*\('
    r'|\bget_allowed_mime_types\s*\('
    # canonical: wp_handle_upload($f, array('mimes' => array(...)))
    r'|["\']mimes["\']\s*=>'
    # content derived type, stronger than any name check
    r'|\b(getimagesize|exif_imagetype|wp_get_image_mime|mime_content_type|finfo_file)\s*\('
    # named allowlists: $allowed_types, $accepted_ext, $valid_mimes, $mime_ok
    r'|\$?\w*(allowed|accepted|valid|permitted|whitelist|safe)\w*_?'
    r'(file_)?(types|type|ext|extension|extensions|mime|mimes)\b'
    r'|\$\w*(mime|ext|type)\w*_(ok|valid|allowed)\b'
    # membership tests against a type or extension map
    r'|\bin_array\s*\(\s*\$?\w*(ext|extension|mime|type)\b'
    r'|\bisset\s*\(\s*\$\w+\s*\[\s*\$?\w*(mime|ext|type)\w*\s*[\]\[]'
    r'|\barray_key_exists\s*\(\s*\$?\w*(mime|ext|type)\b',
    re.I)

# ----------------------------------------------------------------- SQL

# A $wpdb->query or get_* call with an interpolated variable and no prepare() is
# SQL injection, which outranks every other verdict this module can reach.
SQL_CALL = re.compile(
    r'\$wpdb->\s*(query|get_results|get_row|get_var|get_col)\s*\(([^;]{0,400})', re.S)
SQL_PREPARE = re.compile(r'->\s*prepare\s*\(|\besc_sql\s*\(|\bprepare\s*\(', re.I)
SQL_INTERP = re.compile(r'["\'][^"\']*\$\w+|\.\s*\$\w+\s*\.|\{\$\w+')
