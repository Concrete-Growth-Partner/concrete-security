<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Regole .htaccess (funzionano solo su Apache / LiteSpeed).
 * Su nginx vanno chieste all'hosting: la pagina di controllo lo segnala.
 */

define('CS_MARKER', 'Concrete Security');

function cs_is_apache()
{
    global $is_apache;
    return !empty($is_apache);
}

function cs_uploads_htaccess_path()
{
    $up = wp_upload_dir(null, false);
    return trailingslashit($up['basedir']) . '.htaccess';
}

function cs_root_htaccess_path()
{
    if (!function_exists('get_home_path')) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }
    return get_home_path() . '.htaccess';
}

function cs_root_rules()
{
    $files = [];
    if (cs_on('block_sensitive')) {
        $files[] = 'wp-config\.php';
        $files[] = 'wp-config-sample\.php';
        $files[] = '\.env';
        $files[] = 'wp-content/debug\.log';
        $files[] = 'error_log';
    }
    if (cs_on('hide_wp_version')) {
        $files[] = 'readme\.html';
        $files[] = 'license\.txt';
    }
    if (!$files) {
        return [];
    }

    $rules = [
        '<IfModule mod_rewrite.c>',
        'RewriteEngine On',
        'RewriteRule ^(' . implode('|', $files) . ')$ - [F,L]',
    ];
    if (cs_on('block_sensitive')) {
        // Backup e dump lasciati nella cartella principale.
        $rules[] = 'RewriteRule ^[^/]+\.(sql|sql\.gz|bak|old|zip|tar|tar\.gz)$ - [F,L]';
    }
    $rules[] = '</IfModule>';
    return $rules;
}

function cs_uploads_rules()
{
    if (!cs_on('block_uploads_php')) {
        return [];
    }
    return [
        '<FilesMatch "\.(?i:php[0-9]?|phtml|phar|pht)$">',
        '  <IfModule mod_authz_core.c>',
        '    Require all denied',
        '  </IfModule>',
        '  <IfModule !mod_authz_core.c>',
        '    Order allow,deny',
        '    Deny from all',
        '  </IfModule>',
        '</FilesMatch>',
    ];
}

/** Riscrive i blocchi Concrete Security negli .htaccess. */
function cs_htaccess_sync()
{
    if (!function_exists('insert_with_markers')) {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
    }
    $ok = true;

    $root = cs_root_htaccess_path();
    if (file_exists($root) ? is_writable($root) : is_writable(dirname($root))) {
        insert_with_markers($root, CS_MARKER, cs_root_rules());
    } elseif (cs_root_rules()) {
        $ok = false;
    }

    $uploads = cs_uploads_htaccess_path();
    if (cs_uploads_rules() && !is_dir(dirname($uploads))) {
        wp_mkdir_p(dirname($uploads));
    }
    if (file_exists($uploads) ? is_writable($uploads) : is_writable(dirname($uploads))) {
        insert_with_markers($uploads, CS_MARKER, cs_uploads_rules());
    } elseif (cs_uploads_rules()) {
        $ok = false;
    }

    return $ok;
}

function cs_htaccess_remove_all()
{
    if (!function_exists('insert_with_markers')) {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
    }
    foreach ([cs_root_htaccess_path(), cs_uploads_htaccess_path()] as $file) {
        if (file_exists($file) && is_writable($file)) {
            insert_with_markers($file, CS_MARKER, []);
        }
    }
}

/** True se il blocco nel file contiene la regola indicata. */
function cs_htaccess_has($file, $needle)
{
    if (!file_exists($file) || !is_readable($file)) {
        return false;
    }
    if (!function_exists('extract_from_markers')) {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
    }
    $lines = extract_from_markers($file, CS_MARKER);
    return strpos(implode("\n", $lines), $needle) !== false;
}
