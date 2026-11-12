<?php
/**
 * Plugin Name:       Concrete Security
 * Description:       Controlli e protezioni di sicurezza di Concrete Digital. Ogni protezione si attiva singolarmente.
 * Version:           2.0.1
 * Author:            Concrete Digital
 * Author URI:        https://concrete.digital
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Text Domain:       concrete-security
 * Update URI:        https://github.com/Concrete-Growth-Partner/concrete-security.git
 */

if (!defined('ABSPATH')) {
    exit;
}

define('CS_VERSION', '2.0.1');
define('CS_FILE', __FILE__);
define('CS_DIR', plugin_dir_path(__FILE__));
define('CS_URL', plugin_dir_url(__FILE__));

// Repository GitHub da cui arrivano gli aggiornamenti (owner/nome-repo).
define('CS_GITHUB_REPO', 'https://github.com/Concrete-Growth-Partner/concrete-security.git');

require_once CS_DIR . 'includes/settings.php';
require_once CS_DIR . 'includes/hardening.php';
require_once CS_DIR . 'includes/htaccess.php';
require_once CS_DIR . 'includes/login-guard.php';
require_once CS_DIR . 'includes/checks.php';

if (is_admin()) {
    require_once CS_DIR . 'includes/admin.php';
}

/* ------------------------------------------------------------------
 * Aggiornamenti automatici da GitHub
 * ------------------------------------------------------------------ */
$cs_puc = CS_DIR . 'vendor/plugin-update-checker/plugin-update-checker.php';
if (file_exists($cs_puc)) {
    require_once $cs_puc;
    $cs_updater = \YahnisElsts\PluginUpdateChecker\v6\PucFactory::buildUpdateChecker(
        CS_GITHUB_REPO,
        CS_FILE,
        'concrete-security'
    );
    $cs_updater->getVcsApi()->enableReleaseAssets();

    // Repository privato: decommenta e metti un token di SOLA LETTURA.
    // $cs_updater->setAuthentication('github_pat_xxx');
}

// Il nostro plugin si aggiorna sempre in automatico.
add_filter('auto_update_plugin', function ($update, $item) {
    if (isset($item->slug) && $item->slug === 'concrete-security') {
        return true;
    }
    return $update;
}, 10, 2);

/* ------------------------------------------------------------------
 * Attivazione / disattivazione
 * ------------------------------------------------------------------ */
register_activation_hook(__FILE__, function () {
    // Tutto spento di default: salva solo la struttura vuota.
    if (get_option('cs_settings') === false) {
        add_option('cs_settings', []);
    }
    cs_lg_settings(); // crea la chiave di Login Guard
});

register_deactivation_hook(__FILE__, function () {
    // Toglie le regole scritte negli .htaccess.
    cs_htaccess_remove_all();
});

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    array_unshift($links, '<a href="' . esc_url(admin_url('admin.php?page=concrete-security')) . '">Controlli</a>');
    return $links;
});
