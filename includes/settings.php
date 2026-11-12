<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Elenco delle protezioni attivabili, nell'ordine in cui compaiono.
 * Tutte spente di default.
 */
function cs_features()
{
    return [
        'block_enum'           => 'Blocca ricerca nomi utente',
        'login_lockout'        => 'Blocco utente dopo 5 tentativi',
        'generic_login_error'  => 'Messaggio di login generico',
        'short_sessions'       => 'Sessioni più brevi',
        'disable_registration' => 'Chiudi registrazione utenti',
        'disable_xmlrpc'       => 'Chiudi XML-RPC',
        'disable_pingback'     => 'Disattiva pingback',
        'disable_file_edit'    => 'Disattiva editor file',
        'hide_wp_version'      => 'Nascondi versione WordPress',
        'block_sensitive'      => 'Blocca file sensibili',
        'block_uploads_php'    => 'Blocca PHP negli upload',
        'security_headers'     => 'Header di sicurezza',
        'limit_revisions'      => 'Massimo 5 revisioni',
    ];
}

function cs_settings()
{
    $o = get_option('cs_settings', []);
    return is_array($o) ? $o : [];
}

function cs_on($key)
{
    $o = cs_settings();
    return !empty($o[$key]);
}

function cs_extra($key, $default = '')
{
    $o = get_option('cs_extra', []);
    return isset($o[$key]) ? $o[$key] : $default;
}
