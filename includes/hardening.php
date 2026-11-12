<?php
if (!defined('ABSPATH')) {
    exit;
}

/* ================================================================
 * ACCESSI E UTENTI
 * ================================================================ */

/* Blocca ricerca nomi utente ------------------------------------ */
if (cs_on('block_enum')) {

    // REST API /wp/v2/users visibile solo a chi può gestire gli utenti.
    add_filter('rest_endpoints', function ($endpoints) {
        if (current_user_can('list_users')) {
            return $endpoints;
        }
        foreach (array_keys($endpoints) as $route) {
            if (strpos($route, '/wp/v2/users') === 0) {
                unset($endpoints[$route]);
            }
        }
        return $endpoints;
    });

    // ?author=N : bloccato prima del redirect canonico che mostrerebbe il nome.
    add_action('init', function () {
        if (!is_admin() && isset($_GET['author']) && !current_user_can('list_users')) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }, 1);

    // Archivi autore.
    add_action('template_redirect', function () {
        if (is_author() && !current_user_can('list_users')) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }, 1);

    // Sitemap autori.
    add_filter('wp_sitemaps_add_provider', function ($provider, $name) {
        return $name === 'users' ? false : $provider;
    }, 10, 2);

    // Yoast / Rank Math: sitemap autori.
    add_filter('wpseo_sitemap_exclude_author', '__return_true');
    add_filter('rank_math/sitemap/author/query', function ($args) {
        $args['include'] = [0];
        return $args;
    });

    // oEmbed: niente nome e link autore.
    add_filter('oembed_response_data', function ($data) {
        unset($data['author_name'], $data['author_url']);
        return $data;
    });
}

/* Blocco utente dopo 5 tentativi falliti (per 20 minuti) --------- */
if (cs_on('login_lockout')) {

    function cs_lock_key($username, $type)
    {
        return 'cs_' . $type . '_' . md5(strtolower(trim((string) $username)));
    }

    add_filter('authenticate', function ($user, $username) {
        if (empty($username)) {
            return $user;
        }
        if (get_transient(cs_lock_key($username, 'lock'))) {
            return new WP_Error(
                'cs_locked',
                '<strong>Errore:</strong> troppi tentativi falliti. Riprova tra 20 minuti.'
            );
        }
        return $user;
    }, 30, 2);

    add_action('wp_login_failed', function ($username) {
        $count_key = cs_lock_key($username, 'fail');
        $count     = (int) get_transient($count_key) + 1;
        set_transient($count_key, $count, 20 * MINUTE_IN_SECONDS);

        if ($count >= 5) {
            set_transient(cs_lock_key($username, 'lock'), 1, 20 * MINUTE_IN_SECONDS);
            delete_transient($count_key);
        }
    });

    add_action('wp_login', function ($username) {
        delete_transient(cs_lock_key($username, 'fail'));
    });
}

/* Messaggio di login generico ----------------------------------- */
if (cs_on('generic_login_error')) {
    add_filter('login_errors', function ($error) {
        if (strpos($error, 'troppi tentativi') !== false) {
            return $error;
        }
        return '<strong>Errore:</strong> credenziali non valide.';
    });
}

/* Sessioni più brevi -------------------------------------------- */
if (cs_on('short_sessions')) {
    add_filter('auth_cookie_expiration', function ($length, $user_id, $remember) {
        return $remember ? 3 * DAY_IN_SECONDS : 8 * HOUR_IN_SECONDS;
    }, 10, 3);
}

/* Chiudi registrazione utenti ----------------------------------- */
if (cs_on('disable_registration')) {
    add_filter('pre_option_users_can_register', function () {
        return '0';
    });
}

/* ================================================================
 * SUPERFICIE DI ATTACCO
 * ================================================================ */

/* Chiudi XML-RPC ------------------------------------------------ */
if (cs_on('disable_xmlrpc')) {
    add_filter('xmlrpc_enabled', '__return_false');
    remove_action('wp_head', 'rsd_link');

    if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
        status_header(403);
        exit('XML-RPC disattivato.');
    }
}

/* Disattiva pingback -------------------------------------------- */
if (cs_on('disable_pingback')) {
    add_filter('xmlrpc_methods', function ($methods) {
        unset($methods['pingback.ping'], $methods['pingback.extensions.getPingbacks']);
        return $methods;
    });
    add_filter('wp_headers', function ($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    });
    add_filter('pre_option_default_ping_status', function () {
        return 'closed';
    });
    add_action('pre_ping', function (&$links) {
        $links = [];
    });
}

/* Disattiva editor file ----------------------------------------- */
if (cs_on('disable_file_edit') && !defined('DISALLOW_FILE_EDIT')) {
    define('DISALLOW_FILE_EDIT', true);
}

/* Nascondi versione WordPress ----------------------------------- */
if (cs_on('hide_wp_version')) {
    remove_action('wp_head', 'wp_generator');
    add_filter('the_generator', '__return_empty_string');

    $cs_strip_ver = function ($src) {
        if ($src && strpos($src, 'ver=' . get_bloginfo('version')) !== false) {
            $src = remove_query_arg('ver', $src);
        }
        return $src;
    };
    add_filter('style_loader_src', $cs_strip_ver, 9999);
    add_filter('script_loader_src', $cs_strip_ver, 9999);
}
// "Blocca file sensibili" e "Blocca PHP negli upload" sono in htaccess.php

/* ================================================================
 * BROWSER
 * ================================================================ */
if (cs_on('security_headers')) {
    $cs_headers = function () {
        if (headers_sent()) {
            return;
        }
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    };
    add_action('send_headers', $cs_headers);
    add_action('admin_init', $cs_headers);
    add_action('login_init', $cs_headers);
}

/* ================================================================
 * DATABASE
 * ================================================================ */
if (cs_on('limit_revisions')) {
    add_filter('wp_revisions_to_keep', function ($num) {
        return ($num < 0 || $num > 5) ? 5 : $num;
    }, 9999);
}
