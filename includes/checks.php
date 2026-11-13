<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Stati: ok (verde), warn (giallo), bad (rosso), info (grigio).
 * Ogni riga: label, desc, status, detail, toggle (chiave in cs_features o null), link.
 */

function cs_row($label, $desc, $status, $detail, $toggle = null, $link = null)
{
    return compact('label', 'desc', 'status', 'detail', 'toggle', 'link');
}

function cs_admins()
{
    return get_users(['role' => 'administrator', 'fields' => ['ID', 'user_login', 'user_registered', 'display_name']]);
}

function cs_plugin_active($file)
{
    if (!function_exists('is_plugin_active')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    return is_plugin_active($file);
}

function cs_any_plugin_active($files)
{
    foreach ($files as $f) {
        if (cs_plugin_active($f)) {
            return $f;
        }
    }
    return false;
}

function cs_get_checks()
{
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $sections = [];
    $deep     = get_option('cs_deep', []);

    /* ============================================================
     * 1. ACCESSI E UTENTI
     * ============================================================ */
    $rows   = [];
    $admins = cs_admins();

    // 2FA
    if (!cs_plugin_active('wp-2fa/wp-2fa.php')) {
        $rows[] = cs_row('Autenticazione a due fattori', 'Codice a due fattori per gli amministratori (plugin WP 2FA).', 'bad', 'WP 2FA non è attivo.', null, admin_url('plugin-install.php?s=wp-2fa&tab=search&type=term'));
    } else {
        $without = [];
        foreach ($admins as $a) {
            $m = get_user_meta($a->ID, 'wp_2fa_enabled_methods', true);
            if (empty($m)) {
                $without[] = $a->user_login;
            }
        }
        $tot = count($admins);
        $on  = $tot - count($without);
        $rows[] = cs_row(
            'Autenticazione a due fattori',
            'Codice a due fattori per gli amministratori (plugin WP 2FA).',
            $without ? 'warn' : 'ok',
            $without ? "Attiva su $on amministratori su $tot. Senza: " . implode(', ', $without) . '. In WP 2FA → Impostazioni rendila obbligatoria.' : "Attiva su tutti gli amministratori ($tot).",
            null,
            admin_url('admin.php?page=wp-2fa-settings')
        );
    }

    // Nuovi amministratori
    $recent = [];
    foreach ($admins as $a) {
        if (strtotime($a->user_registered . ' UTC') > time() - 7 * DAY_IN_SECONDS) {
            $recent[] = $a->user_login;
        }
    }
    $rows[] = cs_row('Nuovi amministratori', 'Admin creati negli ultimi 7 giorni: se non li conosci, il sito potrebbe essere compromesso.', $recent ? 'bad' : 'ok', $recent ? 'Creati di recente: ' . implode(', ', $recent) . '. Verifica che siano vostri.' : 'Nessun amministratore nuovo. Totale amministratori: ' . count($admins) . '.', null, admin_url('users.php?role=administrator'));

    // Username facili
    $weak  = [];
    $bad_names = ['admin', 'administrator', 'amministratore', 'wordpress', 'root', 'test', 'demo', 'user', 'support'];
    $bad_names[] = sanitize_title(get_bloginfo('name'));
    $bad_names[] = strtolower(preg_replace('/^www\./', '', (string) wp_parse_url(home_url(), PHP_URL_HOST)));
    $bad_names[] = strtolower(explode('.', preg_replace('/^www\./', '', (string) wp_parse_url(home_url(), PHP_URL_HOST)))[0]);
    foreach ($admins as $a) {
        if (in_array(strtolower($a->user_login), array_filter($bad_names), true)) {
            $weak[] = $a->user_login;
        }
    }
    $rows[] = cs_row('Username facili da indovinare', 'Admin con nomi come "admin", "wordpress" o il nome del sito.', $weak ? 'bad' : 'ok', $weak ? 'Da sostituire: ' . implode(', ', $weak) . '. Crea un nuovo admin con username casuale e elimina questo, assegnando i contenuti.' : 'Nessuno username ovvio.', null, admin_url('users.php?role=administrator'));

    // Enumerazione
    $rows[] = cs_row('Blocca ricerca nomi utente', 'Nasconde gli username che WordPress mostra di serie: REST API /wp/v2/users, ?author=1, archivi e sitemap autori, oEmbed.', cs_on('block_enum') ? 'ok' : 'bad', cs_on('block_enum') ? 'Nomi utente nascosti.' : 'Chiunque può leggere gli username degli amministratori.', 'block_enum');

    $rows[] = cs_row('Blocco utente dopo 5 tentativi', 'Dopo 5 password sbagliate quel nome utente resta bloccato 20 minuti, anche se il bot cambia IP a ogni tentativo.', cs_on('login_lockout') ? 'ok' : 'bad', cs_on('login_lockout') ? 'Attivo.' : 'Tentativi illimitati sullo stesso utente.', 'login_lockout');

    $rows[] = cs_row('Messaggio di login generico', 'WordPress dice se l\'utente esiste ("password errata per l\'utente X"). Con questa opzione risponde sempre "credenziali non valide".', cs_on('generic_login_error') ? 'ok' : 'warn', cs_on('generic_login_error') ? 'Attivo.' : 'Il login conferma quali utenti esistono.', 'generic_login_error');

    $rows[] = cs_row('Sessioni più brevi', 'L\'accesso scade dopo 8 ore (3 giorni con "Ricordami"), invece di 2 e 14 giorni.', cs_on('short_sessions') ? 'ok' : 'warn', cs_on('short_sessions') ? 'Attivo.' : 'Durata standard di WordPress.', 'short_sessions');

    $raw_reg = (int) get_option('users_can_register');
    if (cs_on('disable_registration')) {
        $reg_status = 'ok';
        $reg_detail = 'Registrazione chiusa.';
    } else {
        $reg_status = $raw_reg ? 'bad' : 'ok';
        $reg_detail = $raw_reg ? 'Chiunque può registrarsi. Lasciala aperta solo se serve (e-commerce, area riservata).' : 'Già chiusa nelle Impostazioni di WordPress.';
    }
    $rows[] = cs_row('Chiudi registrazione utenti', 'Impedisce di creare account dal sito. Non attivarla su e-commerce o siti con area riservata.', $reg_status, $reg_detail, 'disable_registration');

    $sections[] = ['title' => 'Accessi e utenti', 'rows' => $rows];

    /* ============================================================
     * 2. SUPERFICIE DI ATTACCO
     * ============================================================ */
    $rows   = [];
    $apache = cs_is_apache();
    $nginx_note = ' Il server non è Apache: questa regola va chiesta all\'hosting.';

    $rows[] = cs_row('Chiudi XML-RPC', 'Vecchio canale di accesso remoto usato dai bot per provare migliaia di password in una sola richiesta. Non attivarlo se il sito usa Jetpack o l\'app WordPress.', cs_on('disable_xmlrpc') ? 'ok' : 'bad', cs_on('disable_xmlrpc') ? 'xmlrpc.php risponde 403.' : 'XML-RPC aperto.', 'disable_xmlrpc');

    $rows[] = cs_row('Disattiva pingback', 'I pingback vengono usati per far attaccare altri siti dal tuo (DDoS).', cs_on('disable_pingback') ? 'ok' : 'warn', cs_on('disable_pingback') ? 'Attivo.' : 'Pingback attivi.', 'disable_pingback');

    $rows[] = cs_row('Disattiva commenti', 'Spegne i commenti su tutto il sito: form, invio diretto dei bot, REST API, XML-RPC, feed, menu e widget. I commenti esistenti restano nel database ma non si vedono. Non attivarlo se il sito usa i commenti o le recensioni WooCommerce.', cs_on('disable_comments') ? 'ok' : 'warn', cs_on('disable_comments') ? 'Commenti disattivati.' : 'Commenti attivi: possibile canale di spam.', 'disable_comments');

    $fe_defined = defined('DISALLOW_FILE_EDIT') && DISALLOW_FILE_EDIT;
    $rows[] = cs_row('Disattiva editor file', 'Toglie Aspetto → Editor e Plugin → Editor: chi ruba un admin non può scrivere codice PHP dalla bacheca.', $fe_defined ? 'ok' : 'bad', $fe_defined ? (cs_on('disable_file_edit') ? 'Editor disattivato.' : 'Già disattivato nel wp-config.php.') : 'Editor attivo.', 'disable_file_edit');

    $hv_ok = cs_on('hide_wp_version');
    $hv_detail = $hv_ok ? 'Versione nascosta.' : 'La versione ' . get_bloginfo('version') . ' è visibile nel codice della pagina.';
    if ($hv_ok && !$apache) {
        $hv_detail .= ' readme.html e license.txt:' . $nginx_note;
    }
    $rows[] = cs_row('Nascondi versione WordPress', 'Toglie la versione dal codice delle pagine, da CSS/JS e blocca readme.html e license.txt. I bot cercano versioni note vulnerabili.', $hv_ok ? 'ok' : 'warn', $hv_detail, 'hide_wp_version');

    $bs_on = cs_on('block_sensitive');
    if (!$bs_on) {
        $bs_status = 'bad';
        $bs_detail = 'wp-config.php, debug.log, .env e backup nella cartella principale non sono bloccati dal server.';
    } elseif (!$apache) {
        $bs_status = 'warn';
        $bs_detail = 'Attivo, ma' . $nginx_note;
    } elseif (cs_htaccess_has(cs_root_htaccess_path(), 'wp-config')) {
        $bs_status = 'ok';
        $bs_detail = 'Regole presenti nel .htaccess.';
    } else {
        $bs_status = 'bad';
        $bs_detail = 'Impossibile scrivere il .htaccess principale: controlla i permessi.';
    }
    $rows[] = cs_row('Blocca file sensibili', 'Blocca l\'accesso diretto a wp-config.php, debug.log, .env, error_log e ai backup (.sql, .zip, .bak) lasciati nella cartella principale.', $bs_status, $bs_detail, 'block_sensitive');

    $bu_on = cs_on('block_uploads_php');
    if (!$bu_on) {
        $bu_status = 'bad';
        $bu_detail = 'Un file .php caricato tra le immagini può essere eseguito.';
    } elseif (!$apache) {
        $bu_status = 'warn';
        $bu_detail = 'Attivo, ma' . $nginx_note;
    } elseif (cs_htaccess_has(cs_uploads_htaccess_path(), 'FilesMatch')) {
        $bu_status = 'ok';
        $bu_detail = 'PHP bloccato in wp-content/uploads.';
    } else {
        $bu_status = 'bad';
        $bu_detail = 'Impossibile scrivere wp-content/uploads/.htaccess: controlla i permessi.';
    }
    $rows[] = cs_row('Blocca PHP negli upload', 'Il trucco classico dei malware: caricano un .php tra le immagini e lo eseguono. Questo lo impedisce.', $bu_status, $bu_detail, 'block_uploads_php');

    $sections[] = ['title' => 'Superficie di attacco', 'rows' => $rows];

    /* ============================================================
     * 3. BROWSER
     * ============================================================ */
    $sections[] = ['title' => 'Browser', 'rows' => [
        cs_row('Header di sicurezza', 'X-Frame-Options, X-Content-Type-Options, Referrer-Policy e Permissions-Policy: proteggono da clickjacking e altri attacchi lato browser. Se un iframe del sito su un altro dominio smette di funzionare, spegnilo.', cs_on('security_headers') ? 'ok' : 'warn', cs_on('security_headers') ? 'Header inviati.' : 'Header non inviati dal plugin (potrebbe già farlo l\'hosting).', 'security_headers'),
    ]];

    /* ============================================================
     * 4. PLUGIN E TEMI
     * ============================================================ */
    $rows        = [];
    $all_plugins = get_plugins();
    $active      = (array) get_option('active_plugins', []);
    $inactive    = array_diff(array_keys($all_plugins), $active);
    $inactive_names = array_map(function ($f) use ($all_plugins) {
        return $all_plugins[$f]['Name'];
    }, $inactive);

    $upd = get_site_transient('update_plugins');
    $pending = (isset($upd->response) && is_array($upd->response)) ? count($upd->response) : 0;
    $core = function_exists('get_core_updates') ? get_core_updates() : [];
    $core_pending = false;
    if (!function_exists('get_core_updates')) {
        $cu = get_site_transient('update_core');
        if (isset($cu->updates[0]->response) && $cu->updates[0]->response === 'upgrade') {
            $core_pending = $cu->updates[0]->current;
        }
    } elseif (!empty($core[0]->response) && $core[0]->response === 'upgrade') {
        $core_pending = $core[0]->current;
    }
    $upd_msgs = [];
    if ($core_pending) {
        $upd_msgs[] = 'WordPress ' . $core_pending . ' disponibile';
    }
    if ($pending) {
        $upd_msgs[] = $pending . ' plugin da aggiornare';
    }
    $rows[] = cs_row('Aggiornamenti', 'WordPress e plugin non aggiornati sono la prima causa di siti bucati.', $upd_msgs ? 'bad' : 'ok', $upd_msgs ? implode(' · ', $upd_msgs) . '.' : 'Tutto aggiornato.', null, admin_url('update-core.php'));

    $rows[] = cs_row('Plugin disattivati', 'Un plugin disattivato ma installato può comunque avere vulnerabilità sfruttabili. Se non serve, va eliminato.', $inactive ? 'warn' : 'ok', $inactive ? count($inactive) . ' da eliminare: ' . implode(', ', $inactive_names) . '.' : 'Nessun plugin disattivato.', null, admin_url('plugins.php?plugin_status=inactive'));

    $themes   = wp_get_themes();
    $keep     = [get_stylesheet(), get_template()];
    $extra_th = array_diff(array_keys($themes), $keep);
    $rows[] = cs_row('Temi non usati', 'Basta tenere il tema attivo (e il suo tema padre). Gli altri vanno eliminati.', count($extra_th) > 1 ? 'warn' : 'ok', $extra_th ? count($extra_th) . ' non usati: ' . implode(', ', $extra_th) . '.' : 'Nessun tema in più.', null, admin_url('themes.php'));

    $log_plugin = cs_any_plugin_active(['wp-security-audit-log/wp-security-audit-log.php', 'wp-security-audit-log-premium/wp-security-audit-log.php', 'simple-history/index.php', 'aryo-activity-log/aryo-activity-log.php']);
    $rows[] = cs_row('Registro attività', 'Registra login, tentativi falliti e modifiche: senza, non sai se qualcuno sta provando a entrare.', $log_plugin ? 'ok' : 'bad', $log_plugin ? 'Attivo (' . dirname($log_plugin) . ').' : 'Nessun plugin di registro attività. Installa WP Activity Log o Simple History.', null, $log_plugin ? null : admin_url('plugin-install.php?s=activity+log&tab=search&type=term'));

    $backup = cs_any_plugin_active(['updraftplus/updraftplus.php', 'backwpup/backwpup.php', 'duplicator/duplicator.php', 'duplicator-pro/duplicator-pro.php', 'all-in-one-wp-migration/all-in-one-wp-migration.php', 'wpvivid-backuprestore/wpvivid-backuprestore.php', 'backup-backup/backup-backup.php', 'jetpack/jetpack.php', 'blogvault-real-time-backup/blogvault.php']);
    $rows[] = cs_row('Backup', 'Un plugin di backup attivo, a meno che i backup non li faccia già l\'hosting.', $backup ? 'ok' : 'warn', $backup ? 'Attivo (' . dirname($backup) . ').' : 'Nessun plugin di backup. Verifica che l\'hosting faccia backup automatici.', null);

    // Approfonditi
    if (isset($deep['abandoned'])) {
        $ab = $deep['abandoned'];
        $rows[] = cs_row('Plugin abbandonati', 'Plugin non aggiornati da più di 2 anni o rimossi dal repository di WordPress: nessuno corregge più le falle.', $ab ? 'warn' : 'ok', $ab ? implode(' · ', $ab) : 'Nessun plugin abbandonato.', null);
    }
    if (isset($deep['vulns'])) {
        $v = $deep['vulns'];
        if ($v === 'no_token') {
            $rows[] = cs_row('Vulnerabilità note', 'Confronto dei plugin installati con il database WPScan.', 'info', 'Inserisci un token WPScan gratuito qui sotto in "Impostazioni" per attivare il controllo.', null);
        } else {
            $rows[] = cs_row('Vulnerabilità note', 'Confronto dei plugin installati con il database WPScan.', $v ? 'bad' : 'ok', $v ? implode(' · ', $v) : 'Nessuna vulnerabilità nota sulle versioni installate.', null);
        }
    }
    $sections[] = ['title' => 'Plugin e temi', 'rows' => $rows];

    /* ============================================================
     * 5. FILE E SERVER
     * ============================================================ */
    $rows = [];

    $https = (strpos(home_url(), 'https://') === 0) && (strpos(site_url(), 'https://') === 0);
    $https_detail = $https ? 'Sito su HTTPS.' : 'L\'indirizzo del sito non è https://.';
    $https_status = $https ? 'ok' : 'bad';
    if (isset($deep['ssl_days'])) {
        if ($deep['ssl_days'] === null) {
            $https_detail .= ' Scadenza certificato non leggibile.';
        } elseif ($deep['ssl_days'] < 0) {
            $https_status = 'bad';
            $https_detail .= ' Certificato SCADUTO.';
        } else {
            if ($deep['ssl_days'] < 15) {
                $https_status = 'warn';
            }
            $https_detail .= ' Il certificato scade tra ' . (int) $deep['ssl_days'] . ' giorni.';
        }
    }
    $rows[] = cs_row('HTTPS e certificato', 'Il sito deve usare https:// con un certificato valido.', $https_status, $https_detail, null);

    $php = PHP_VERSION;
    $rows[] = cs_row('Versione PHP', 'PHP fuori supporto non riceve più correzioni di sicurezza. Minimo consigliato: 8.1.', version_compare($php, '8.1', '>=') ? 'ok' : (version_compare($php, '7.4', '>=') ? 'warn' : 'bad'), 'PHP ' . $php . '.', null);

    $debug_log = defined('WP_DEBUG_LOG') && WP_DEBUG_LOG;
    $debug_display = defined('WP_DEBUG') && WP_DEBUG && (!defined('WP_DEBUG_DISPLAY') || WP_DEBUG_DISPLAY);
    $log_file = (defined('WP_DEBUG_LOG') && is_string(WP_DEBUG_LOG)) ? WP_DEBUG_LOG : WP_CONTENT_DIR . '/debug.log';
    $dmsg = [];
    if ($debug_display) {
        $dmsg[] = 'gli errori vengono mostrati ai visitatori';
    }
    if ($debug_log) {
        $dmsg[] = 'WP_DEBUG_LOG è attivo';
    }
    if (file_exists($log_file)) {
        $dmsg[] = 'esiste ' . str_replace(ABSPATH, '', $log_file) . ' (' . size_format(filesize($log_file)) . ')';
    }
    $rows[] = cs_row('Debug', 'In produzione WP_DEBUG va spento e il file debug.log non deve essere leggibile.', $dmsg ? ($debug_display ? 'bad' : 'warn') : 'ok', $dmsg ? ucfirst(implode(', ', $dmsg)) . '. Nel wp-config.php metti WP_DEBUG e WP_DEBUG_LOG a false' . (file_exists($log_file) ? ' ed elimina il file di log.' : '.') : 'Debug spento.', null);

    $cfg = file_exists(ABSPATH . 'wp-config.php') ? ABSPATH . 'wp-config.php' : (file_exists(dirname(ABSPATH) . '/wp-config.php') ? dirname(ABSPATH) . '/wp-config.php' : '');
    if ($cfg) {
        $perm  = fileperms($cfg) & 0777;
        $world = $perm & 0002;
        $rows[] = cs_row('Permessi wp-config.php', 'Il file con le password del database non deve essere scrivibile da tutti. Consigliati 640 o 600.', $world ? 'bad' : 'ok', 'Permessi attuali: ' . substr(sprintf('%o', $perm), -3) . '.', null);
    }

    $salt_keys = ['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'];
    $bad_salt  = [];
    foreach ($salt_keys as $k) {
        if (!defined($k) || constant($k) === '' || stripos(constant($k), 'put your unique phrase') !== false || strlen(constant($k)) < 32) {
            $bad_salt[] = $k;
        }
    }
    $rows[] = cs_row('Chiavi di sicurezza (salt)', 'Le 8 chiavi nel wp-config.php proteggono i cookie di accesso. Rigenerarle disconnette tutti (utile dopo un attacco).', $bad_salt ? 'bad' : 'ok', $bad_salt ? 'Mancanti o deboli: ' . implode(', ', $bad_salt) . '. Generale da api.wordpress.org/secret-key/1.1/salt/.' : 'Tutte presenti.', null);

    global $wpdb;
    $rows[] = cs_row('Prefisso database', 'Il prefisso standard "wp_" rende un po\' più facili gli attacchi SQL automatici. Solo informativo: cambiarlo su un sito esistente è rischioso.', $wpdb->prefix === 'wp_' ? 'info' : 'ok', 'Prefisso attuale: ' . $wpdb->prefix, null);

    if (isset($deep['suspicious'])) {
        $s = $deep['suspicious'];
        $rows[] = cs_row('File sospetti', 'File .php in uploads, plugin con nomi casuali (es. site-tweaks-dee4b382d5), file in mu-plugins.', $s ? 'bad' : 'ok', $s ? implode(' · ', $s) : 'Nessun file sospetto.', null);
    }
    if (isset($deep['core'])) {
        $c = $deep['core'];
        if ($c === null) {
            $rows[] = cs_row('File di WordPress modificati', 'Confronto dei file di WordPress con quelli ufficiali.', 'info', 'Impossibile scaricare i checksum ufficiali.', null);
        } else {
            $rows[] = cs_row('File di WordPress modificati', 'Confronto dei file di WordPress con quelli ufficiali.', $c ? 'bad' : 'ok', $c ? count($c) . ' file diversi dall\'originale: ' . implode(', ', array_slice($c, 0, 15)) . (count($c) > 15 ? '…' : '') . '. Reinstalla WordPress da Bacheca → Aggiornamenti.' : 'Tutti i file corrispondono all\'originale.', null);
        }
    }
    $sections[] = ['title' => 'File e server', 'rows' => $rows];

    /* ============================================================
     * 6. DATABASE
     * ============================================================ */
    $revs = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = 'revision'");
    $sections[] = ['title' => 'Database', 'rows' => [
        cs_row('Massimo 5 revisioni', 'Tiene solo le ultime 5 revisioni per pagina: evita che il database si gonfi. Le revisioni già esistenti vanno pulite a parte (es. WP-Optimize, dopo un backup).', cs_on('limit_revisions') ? ($revs > 1000 ? 'warn' : 'ok') : ($revs > 1000 ? 'bad' : 'warn'), number_format_i18n($revs) . ' revisioni nel database.' . (cs_on('limit_revisions') ? '' : ' Nessun limite.'), 'limit_revisions'),
    ]];

    return $sections;
}

/* ================================================================
 * CONTROLLI APPROFONDITI (eseguiti su richiesta)
 * ================================================================ */
function cs_run_deep_checks()
{
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    if (!function_exists('plugins_api')) {
        require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
    }
    @set_time_limit(120);
    $out     = ['time' => time()];
    $plugins = get_plugins();

    /* Plugin abbandonati */
    $ab = [];
    foreach ($plugins as $file => $data) {
        $slug = dirname($file);
        if ($slug === '.' || $slug === 'concrete-security') {
            continue;
        }
        $info = plugins_api('plugin_information', ['slug' => $slug, 'fields' => ['last_updated' => true, 'sections' => false]]);
        if (is_wp_error($info)) {
            $msg = $info->get_error_message();
            if (stripos($msg, 'closed') !== false) {
                $ab[] = $data['Name'] . ' (rimosso dal repository)';
            }
            continue; // plugin premium/custom: non sul repository
        }
        if (!empty($info->last_updated) && strtotime($info->last_updated) < strtotime('-2 years')) {
            $ab[] = $data['Name'] . ' (ultimo aggiornamento ' . date_i18n('m/Y', strtotime($info->last_updated)) . ')';
        }
    }
    $out['abandoned'] = $ab;

    /* Vulnerabilità WPScan */
    $token = trim(cs_extra('wpscan_token'));
    if ($token === '') {
        $out['vulns'] = 'no_token';
    } else {
        $v = [];
        foreach ($plugins as $file => $data) {
            $slug = dirname($file);
            if ($slug === '.' || $slug === 'concrete-security') {
                continue;
            }
            $r = wp_remote_get('https://wpscan.com/api/v3/plugins/' . rawurlencode($slug), [
                'timeout' => 10,
                'headers' => ['Authorization' => 'Token token=' . $token],
            ]);
            if (is_wp_error($r) || wp_remote_retrieve_response_code($r) !== 200) {
                continue;
            }
            $json = json_decode(wp_remote_retrieve_body($r), true);
            if (empty($json[$slug]['vulnerabilities'])) {
                continue;
            }
            foreach ($json[$slug]['vulnerabilities'] as $vuln) {
                $fixed = isset($vuln['fixed_in']) ? $vuln['fixed_in'] : null;
                if ($fixed === null || version_compare($data['Version'], $fixed, '<')) {
                    $v[] = $data['Name'] . ' ' . $data['Version'] . ': ' . $vuln['title'] . ($fixed ? ' (risolta in ' . $fixed . ')' : ' (non ancora risolta)');
                }
            }
        }
        $out['vulns'] = $v;
    }

    /* Scadenza certificato */
    $out['ssl_days'] = null;
    $host = wp_parse_url(home_url(), PHP_URL_HOST);
    if ($host && function_exists('stream_socket_client') && function_exists('openssl_x509_parse')) {
        $ctx = stream_context_create(['ssl' => ['capture_peer_cert' => true, 'verify_peer' => false, 'verify_peer_name' => false, 'SNI_enabled' => true, 'peer_name' => $host]]);
        $s   = @stream_socket_client('ssl://' . $host . ':443', $errno, $errstr, 8, STREAM_CLIENT_CONNECT, $ctx);
        if ($s) {
            $params = stream_context_get_params($s);
            if (!empty($params['options']['ssl']['peer_certificate'])) {
                $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
                if (!empty($cert['validTo_time_t'])) {
                    $out['ssl_days'] = (int) floor(($cert['validTo_time_t'] - time()) / DAY_IN_SECONDS);
                }
            }
            fclose($s);
        }
    }

    /* File sospetti */
    $sus = [];
    $up  = wp_upload_dir(null, false);
    if (is_dir($up['basedir'])) {
        $found = [];
        try {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($up['basedir'], FilesystemIterator::SKIP_DOTS));
            $n  = 0;
            foreach ($it as $f) {
                if (++$n > 50000) {
                    break;
                }
                if ($f->isFile() && preg_match('/\.(php[0-9]?|phtml|phar|pht)$/i', $f->getFilename()) && $f->getFilename() !== 'index.php') {
                    $found[] = str_replace(ABSPATH, '', $f->getPathname());
                }
            }
        } catch (Exception $e) {
        }
        if ($found) {
            $sus[] = count($found) . ' file PHP in uploads: ' . implode(', ', array_slice($found, 0, 10)) . (count($found) > 10 ? '…' : '');
        }
    }
    if (is_dir(WPMU_PLUGIN_DIR)) {
        $mu = array_diff(scandir(WPMU_PLUGIN_DIR), ['.', '..', 'index.php']);
        if ($mu) {
            $sus[] = 'mu-plugins contiene: ' . implode(', ', $mu) . ' (controlla che siano dell\'hosting o vostri)';
        }
    }
    foreach (array_keys($plugins) as $file) {
        $slug = dirname($file);
        if (preg_match('/-[0-9a-f]{8,}$/i', $slug)) {
            $sus[] = 'Plugin con nome casuale: ' . $slug;
        }
    }
    $out['suspicious'] = $sus;

    /* Checksum dei file di WordPress */
    global $wp_version, $wp_local_package;
    if (!function_exists('get_core_checksums')) {
        require_once ABSPATH . 'wp-admin/includes/update.php';
    }
    $sums = get_core_checksums($wp_version, isset($wp_local_package) ? $wp_local_package : 'en_US');
    if (!is_array($sums)) {
        $sums = get_core_checksums($wp_version, 'en_US');
    }
    if (!is_array($sums)) {
        $out['core'] = null;
    } else {
        $diff = [];
        foreach ($sums as $path => $md5) {
            if (strpos($path, 'wp-content/') === 0) {
                continue;
            }
            $full = ABSPATH . $path;
            if (file_exists($full) && md5_file($full) !== $md5) {
                $diff[] = $path;
            }
        }
        // readme/license cambiano con le traduzioni: non contano.
        $out['core'] = array_values(array_diff($diff, ['readme.html', 'license.txt', 'wp-config-sample.php']));
    }

    update_option('cs_deep', $out, false);
    return $out;
}
