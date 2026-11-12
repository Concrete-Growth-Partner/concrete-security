<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * LOGIN GUARD
 * Backoffice e pagina di login accessibili solo dagli IP autorizzati
 * o da chi ha aperto il link con la chiave segreta.
 *
 * Emergenza (chiusa fuori): aggiungi in wp-config.php
 *   define('CS_LOGIN_GUARD_OFF', true);
 */

function cs_lg_settings()
{
    $lg = get_option('cs_login_guard');
    if (!is_array($lg)) {
        $lg = [];
    }
    $lg = wp_parse_args($lg, [
        'enabled'   => 0,
        'ips'       => '',
        'ip_source' => 'REMOTE_ADDR',
        'key'       => '',
        'days'      => 30,
    ]);
    if ($lg['key'] === '') {
        $lg['key'] = wp_generate_password(32, false, false);
        update_option('cs_login_guard', $lg, false);
    }
    return $lg;
}

function cs_lg_ip_sources()
{
    return [
        'REMOTE_ADDR'           => 'Standard (REMOTE_ADDR)',
        'HTTP_CF_CONNECTING_IP' => 'Cloudflare (CF-Connecting-IP)',
        'HTTP_X_FORWARDED_FOR'  => 'Proxy (X-Forwarded-For)',
        'HTTP_X_REAL_IP'        => 'Proxy (X-Real-IP)',
    ];
}

function cs_lg_client_ip($source = null)
{
    if ($source === null) {
        $source = cs_lg_settings()['ip_source'];
    }
    if (!array_key_exists($source, cs_lg_ip_sources())) {
        $source = 'REMOTE_ADDR';
    }
    $raw = isset($_SERVER[$source]) ? (string) $_SERVER[$source] : '';
    $ip  = trim(explode(',', $raw)[0]);
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
}

function cs_lg_ip_list($text)
{
    $out = [];
    foreach (preg_split('/[\s,]+/', (string) $text) as $line) {
        $line = trim(preg_replace('/#.*$/', '', $line));
        if ($line !== '') {
            $out[] = $line;
        }
    }
    return array_values(array_unique($out));
}

function cs_lg_ip_match($ip, $rule)
{
    if ($ip === '' || $rule === '') {
        return false;
    }
    if (strpos($rule, '/') === false) {
        return $ip === $rule;
    }
    // CIDR IPv4
    list($subnet, $bits) = explode('/', $rule, 2);
    $bits = (int) $bits;
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || $bits < 0 || $bits > 32) {
        return false;
    }
    $mask = $bits === 0 ? 0 : (-1 << (32 - $bits)) & 0xFFFFFFFF;
    return (ip2long($ip) & $mask) === (ip2long($subnet) & $mask);
}

function cs_lg_cookie_value($lg)
{
    return hash_hmac('sha256', 'cs_login_guard', $lg['key'] . wp_salt('auth'));
}

function cs_lg_set_cookie($lg)
{
    $days = max(1, (int) $lg['days']);
    setcookie('cs_lg', cs_lg_cookie_value($lg), [
        'expires'  => time() + $days * DAY_IN_SECONDS,
        'path'     => COOKIEPATH ?: '/',
        'domain'   => COOKIE_DOMAIN ?: '',
        'secure'   => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    $_COOKIE['cs_lg'] = cs_lg_cookie_value($lg);
}

/** L'utente corrente può entrare? */
function cs_lg_allowed($lg = null)
{
    if ($lg === null) {
        $lg = cs_lg_settings();
    }
    if (!empty($_COOKIE['cs_lg']) && hash_equals(cs_lg_cookie_value($lg), (string) $_COOKIE['cs_lg'])) {
        return true;
    }
    $ip = cs_lg_client_ip($lg['ip_source']);
    foreach (cs_lg_ip_list($lg['ips']) as $rule) {
        if (cs_lg_ip_match($ip, $rule)) {
            return true;
        }
    }
    return false;
}

function cs_lg_access_url($lg = null)
{
    if ($lg === null) {
        $lg = cs_lg_settings();
    }
    return add_query_arg('cs_key', rawurlencode($lg['key']), wp_login_url());
}

add_action('init', function () {
    if (defined('CS_LOGIN_GUARD_OFF') && CS_LOGIN_GUARD_OFF) {
        return;
    }
    if (wp_doing_ajax() || wp_doing_cron() || (defined('WP_CLI') && WP_CLI) || (defined('REST_REQUEST') && REST_REQUEST)) {
        return;
    }

    $lg = cs_lg_settings();
    if (empty($lg['enabled'])) {
        return;
    }

    $script   = basename(isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '');
    $is_login = ($script === 'wp-login.php');
    $is_admin = is_admin() && !in_array($script, ['admin-ajax.php', 'admin-post.php'], true);

    if (!$is_login && !$is_admin) {
        return;
    }

    // Pagine protette da password: devono restare accessibili ai visitatori.
    if ($is_login && isset($_GET['action']) && $_GET['action'] === 'postpass') {
        return;
    }

    // Link con chiave segreta: imposta il cookie e va al login.
    if ($is_login && isset($_GET['cs_key'])) {
        if (hash_equals($lg['key'], (string) wp_unslash($_GET['cs_key']))) {
            cs_lg_set_cookie($lg);
            wp_safe_redirect(remove_query_arg('cs_key'));
            exit;
        }
    }

    if (cs_lg_allowed($lg)) {
        return;
    }

    status_header(403);
    nocache_headers();
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Accesso non consentito</title></head>'
        . '<body style="font-family:system-ui,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0;background:#f5f5f4;color:#1c1917">'
        . '<p style="font-size:18px">Accesso non consentito.</p></body></html>';
    exit;
}, 1);
