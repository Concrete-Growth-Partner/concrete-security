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

/* Disattiva commenti -------------------------------------------- */
if (cs_on('disable_comments')) {

    // Supporto commenti e trackback tolto da tutti i post type.
    add_action('init', function () {
        foreach (get_post_types() as $post_type) {
            if (post_type_supports($post_type, 'comments')) {
                remove_post_type_support($post_type, 'comments');
            }
            if (post_type_supports($post_type, 'trackbacks')) {
                remove_post_type_support($post_type, 'trackbacks');
            }
        }
    }, 100);

    // Chiusi anche sui contenuti vecchi; commenti esistenti nascosti.
    add_filter('comments_open', '__return_false', 9999);
    add_filter('pings_open', '__return_false', 9999);
    add_filter('comments_array', '__return_empty_array', 9999);
    add_filter('get_comments_number', '__return_zero', 9999);

    // Bot che postano direttamente su wp-comments-post.php.
    add_action('pre_comment_on_post', function () {
        wp_die('Commenti disattivati.', '', ['response' => 403]);
    });

    // Admin: menu, pagine e metabox.
    add_action('admin_menu', function () {
        remove_menu_page('edit-comments.php');
        remove_submenu_page('options-general.php', 'options-discussion.php');
    }, 999);

    add_action('admin_init', function () {
        global $pagenow;
        if (in_array($pagenow, ['edit-comments.php', 'comment.php', 'options-discussion.php'], true)) {
            wp_safe_redirect(admin_url());
            exit;
        }
        remove_meta_box('dashboard_recent_comments', 'dashboard', 'normal');
        foreach (get_post_types() as $post_type) {
            remove_meta_box('commentstatusdiv', $post_type, 'normal');
            remove_meta_box('commentsdiv', $post_type, 'normal');
            remove_meta_box('trackbacksdiv', $post_type, 'normal');
        }
    });

    add_action('admin_bar_menu', function ($bar) {
        $bar->remove_node('comments');
    }, 999);

    // REST API e XML-RPC (strpos al posto di str_starts_with: il plugin supporta PHP 7.4).
    add_filter('rest_endpoints', function ($endpoints) {
        foreach (array_keys($endpoints) as $route) {
            if (strpos($route, '/wp/v2/comments') === 0) {
                unset($endpoints[$route]);
            }
        }
        return $endpoints;
    });

    add_filter('xmlrpc_methods', function ($methods) {
        foreach (array_keys($methods) as $m) {
            if (stripos($m, 'comment') !== false) {
                unset($methods[$m]);
            }
        }
        return $methods;
    });

    // Feed commenti.
    add_filter('feed_links_show_comments_feed', '__return_false');
    add_action('template_redirect', function () {
        if (is_comment_feed()) {
            wp_die('Feed commenti disattivato.', '', ['response' => 404]);
        }
    }, 1);

    // Widget, script e blocchi Gutenberg dei commenti.
    add_action('widgets_init', function () {
        unregister_widget('WP_Widget_Recent_Comments');
        add_filter('show_recent_comments_widget_style', '__return_false');
    });

    add_action('wp_enqueue_scripts', function () {
        wp_deregister_script('comment-reply');
    }, 100);

    add_filter('allowed_block_types_all', function ($allowed, $context) {
        if ($allowed === true) {
            $allowed = array_keys(WP_Block_Type_Registry::get_instance()->get_all_registered());
        }
        return array_values(array_filter((array) $allowed, function ($block) {
            return strpos($block, 'core/comment') !== 0 && $block !== 'core/latest-comments' && $block !== 'core/post-comments-form';
        }));
    }, 10, 2);
}
