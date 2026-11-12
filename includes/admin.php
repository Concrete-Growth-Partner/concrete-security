<?php
if (!defined('ABSPATH')) {
    exit;
}

/* ================================================================
 * MENU
 * ================================================================ */
add_action('admin_menu', function () {
    add_menu_page('Concrete Security', 'Concrete Security', 'manage_options', 'concrete-security', 'cs_render_main', 'dashicons-shield', 80);
    add_submenu_page('concrete-security', 'Controlli di sicurezza', 'Controlli', 'manage_options', 'concrete-security', 'cs_render_main');
    add_submenu_page('concrete-security', 'Login Guard', 'Login Guard', 'manage_options', 'cs-login-guard', 'cs_render_login_guard');
});

add_action('admin_enqueue_scripts', function ($hook) {
    if (strpos($hook, 'concrete-security') === false && strpos($hook, 'cs-login-guard') === false) {
        return;
    }
    wp_enqueue_style('cs-admin', CS_URL . 'assets/admin.css', [], CS_VERSION);
    wp_enqueue_script('cs-admin', CS_URL . 'assets/admin.js', [], CS_VERSION, true);
});

/* ================================================================
 * SALVATAGGI
 * ================================================================ */
function cs_guard_request($action)
{
    if (!current_user_can('manage_options')) {
        wp_die('Permessi insufficienti.');
    }
    check_admin_referer($action);
}

function cs_redirect($page, $msg)
{
    wp_safe_redirect(add_query_arg(['page' => $page, 'cs_msg' => $msg], admin_url('admin.php')));
    exit;
}

add_action('admin_post_cs_save_features', function () {
    cs_guard_request('cs_save_features');
    $posted = isset($_POST['cs']) && is_array($_POST['cs']) ? $_POST['cs'] : [];
    $new    = [];
    foreach (array_keys(cs_features()) as $key) {
        $new[$key] = !empty($posted[$key]) ? 1 : 0;
    }
    update_option('cs_settings', $new);

    $extra = get_option('cs_extra', []);
    if (!is_array($extra)) {
        $extra = [];
    }
    $extra['wpscan_token'] = isset($_POST['wpscan_token']) ? sanitize_text_field(wp_unslash($_POST['wpscan_token'])) : '';
    update_option('cs_extra', $extra, false);

    $ok = cs_htaccess_sync();
    cs_redirect('concrete-security', $ok ? 'saved' : 'saved_htaccess');
});

add_action('admin_post_cs_deep', function () {
    cs_guard_request('cs_deep');
    cs_run_deep_checks();
    cs_redirect('concrete-security', 'deep');
});

add_action('admin_post_cs_save_lg', function () {
    cs_guard_request('cs_save_lg');
    $lg = cs_lg_settings();

    $lg['enabled']   = !empty($_POST['enabled']) ? 1 : 0;
    $src             = isset($_POST['ip_source']) ? sanitize_text_field(wp_unslash($_POST['ip_source'])) : 'REMOTE_ADDR';
    $lg['ip_source'] = array_key_exists($src, cs_lg_ip_sources()) ? $src : 'REMOTE_ADDR';
    $lg['days']      = isset($_POST['days']) ? max(1, min(365, (int) $_POST['days'])) : 30;

    $valid = [];
    foreach (cs_lg_ip_list(isset($_POST['ips']) ? wp_unslash($_POST['ips']) : '') as $rule) {
        $base = explode('/', $rule)[0];
        if (filter_var($base, FILTER_VALIDATE_IP)) {
            $valid[] = $rule;
        }
    }
    $lg['ips'] = implode("\n", $valid);
    update_option('cs_login_guard', $lg, false);

    // Chi attiva Login Guard non deve chiudersi fuori.
    if ($lg['enabled'] && !cs_lg_allowed($lg)) {
        cs_lg_set_cookie($lg);
    }
    cs_redirect('cs-login-guard', 'saved');
});

add_action('admin_post_cs_lg_new_key', function () {
    cs_guard_request('cs_lg_new_key');
    $lg        = cs_lg_settings();
    $lg['key'] = wp_generate_password(32, false, false);
    update_option('cs_login_guard', $lg, false);
    cs_lg_set_cookie($lg); // il vecchio cookie non vale più: rinnova il tuo
    cs_redirect('cs-login-guard', 'newkey');
});

/* ================================================================
 * COMPONENTI
 * ================================================================ */
function cs_status_label($s)
{
    $map = ['ok' => 'OK', 'warn' => 'Da guardare', 'bad' => 'Da sistemare', 'info' => 'Info'];
    return isset($map[$s]) ? $map[$s] : '';
}

function cs_notice()
{
    if (empty($_GET['cs_msg'])) {
        return;
    }
    $msgs = [
        'saved'          => ['ok', 'Impostazioni salvate.'],
        'saved_htaccess' => ['warn', 'Impostazioni salvate, ma non è stato possibile scrivere uno dei file .htaccess. Controlla i permessi o chiedi all\'hosting.'],
        'deep'           => ['ok', 'Controlli approfonditi completati.'],
        'newkey'         => ['ok', 'Nuova chiave generata. Il vecchio link non funziona più: manda quello nuovo al team.'],
    ];
    $m = sanitize_key($_GET['cs_msg']);
    if (isset($msgs[$m])) {
        printf('<div class="cs-notice cs-notice--%s">%s</div>', esc_attr($msgs[$m][0]), esc_html($msgs[$m][1]));
    }
}

function cs_switch($name, $checked, $label)
{
    printf(
        '<label class="cs-switch"><input type="checkbox" name="%s" value="1" %s><span class="cs-switch__track" aria-hidden="true"></span><span class="screen-reader-text">%s</span></label>',
        esc_attr($name),
        checked($checked, true, false),
        esc_html($label)
    );
}

/* ================================================================
 * PAGINA PRINCIPALE
 * ================================================================ */
function cs_render_main()
{
    $sections = cs_get_checks();
    $count    = ['ok' => 0, 'warn' => 0, 'bad' => 0, 'info' => 0];
    foreach ($sections as $sec) {
        foreach ($sec['rows'] as $r) {
            $count[$r['status']]++;
        }
    }
    $lg   = cs_lg_settings();
    $deep = get_option('cs_deep', []);
    ?>
    <div class="wrap cs">
        <header class="cs-head">
            <div>
                <h1 class="cs-title">Concrete Security</h1>
                <p class="cs-sub">Stato di sicurezza di <strong><?php echo esc_html(wp_parse_url(home_url(), PHP_URL_HOST)); ?></strong> · v<?php echo esc_html(CS_VERSION); ?></p>
            </div>
            <div class="cs-summary">
                <span class="cs-pill cs-pill--bad"><?php echo (int) $count['bad']; ?> da sistemare</span>
                <span class="cs-pill cs-pill--warn"><?php echo (int) $count['warn']; ?> da guardare</span>
                <span class="cs-pill cs-pill--ok"><?php echo (int) $count['ok']; ?> ok</span>
            </div>
        </header>

        <?php cs_notice(); ?>

        <?php $lg_st = $lg['enabled'] ? 'ok' : 'bad'; ?>
        <section class="cs-card cs-lgcard cs-lgcard--<?php echo $lg_st; ?>">
            <div class="cs-lgcard__text">
                <span class="cs-dot cs-dot--<?php echo $lg_st; ?>"></span>
                <div>
                    <h2>Login Guard <span class="cs-tag cs-tag--<?php echo $lg_st; ?>"><?php echo $lg['enabled'] ? 'Attivo' : 'Spento'; ?></span></h2>
                    <p><?php echo $lg['enabled'] ? 'Attivo: il backoffice è accessibile solo dagli IP autorizzati o con la chiave del team.' : 'Spento. Blocca il backoffice a tutti tranne IP autorizzati e chi ha la chiave segreta.'; ?></p>
                </div>
            </div>
            <a class="cs-btn" href="<?php echo esc_url(admin_url('admin.php?page=cs-login-guard')); ?>">Configura Login Guard →</a>
        </section>

        <div class="cs-deepbar">
            <p>
                <?php if (!empty($deep['time'])) : ?>
                    Controlli approfonditi eseguiti il <?php echo esc_html(date_i18n('d/m/Y H:i', $deep['time'] + (int) (get_option('gmt_offset') * HOUR_IN_SECONDS))); ?>.
                <?php else : ?>
                    I controlli approfonditi (vulnerabilità, plugin abbandonati, file sospetti, file di WordPress modificati, certificato) non sono ancora stati eseguiti.
                <?php endif; ?>
            </p>
            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="cs_deep">
                <?php wp_nonce_field('cs_deep'); ?>
                <button class="cs-btn cs-btn--ghost" type="submit" data-cs-loading="Controllo in corso…">Esegui controlli approfonditi</button>
            </form>
        </div>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="cs-form">
            <input type="hidden" name="action" value="cs_save_features">
            <?php wp_nonce_field('cs_save_features'); ?>

            <?php foreach ($sections as $i => $sec) : ?>
                <section class="cs-card">
                    <h2 class="cs-card__title"><span class="cs-num"><?php echo (int) $i + 1; ?></span><?php echo esc_html($sec['title']); ?></h2>
                    <div class="cs-cols cs-grid" aria-hidden="true"><span>Controllo</span><span>Stato di questo sito</span><span>Protezione</span></div>
                    <?php foreach ($sec['rows'] as $r) : ?>
                        <div class="cs-row cs-grid">
                            <div class="cs-row__check">
                                <span class="cs-dot cs-dot--<?php echo esc_attr($r['status']); ?>" title="<?php echo esc_attr(cs_status_label($r['status'])); ?>"></span>
                                <div>
                                    <div class="cs-row__label"><?php echo esc_html($r['label']); ?></div>
                                    <p class="cs-row__desc"><?php echo esc_html($r['desc']); ?></p>
                                </div>
                            </div>
                            <div class="cs-state cs-state--<?php echo esc_attr($r['status']); ?>">
                                <span class="cs-tag cs-tag--<?php echo esc_attr($r['status']); ?>"><?php echo esc_html(cs_status_label($r['status'])); ?></span>
                                <p class="cs-row__detail"><?php echo esc_html($r['detail']); ?></p>
                            </div>
                            <div class="cs-row__action">
                                <?php if ($r['toggle']) : ?>
                                    <?php cs_switch('cs[' . $r['toggle'] . ']', cs_on($r['toggle']), $r['label']); ?>
                                <?php elseif ($r['link']) : ?>
                                    <a class="cs-link" href="<?php echo esc_url($r['link']); ?>">Apri →</a>
                                <?php else : ?>
                                    <span class="cs-muted">Solo controllo</span>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </section>
            <?php endforeach; ?>

            <section class="cs-card">
                <h2 class="cs-card__title"><span class="cs-num">⚙</span>Impostazioni</h2>
                <div class="cs-field">
                    <label for="cs-wpscan">Token API WPScan</label>
                    <input id="cs-wpscan" type="password" name="wpscan_token" value="<?php echo esc_attr(cs_extra('wpscan_token')); ?>" autocomplete="off">
                    <p class="cs-row__desc">Serve per il controllo delle vulnerabilità note. Token gratuito su wpscan.com (25 richieste al giorno: una per plugin).</p>
                </div>
            </section>

            <div class="cs-savebar">
                <span class="cs-muted">Le protezioni si applicano subito dopo il salvataggio.</span>
                <button type="submit" class="cs-btn">Salva</button>
            </div>
        </form>
    </div>
    <?php
}

/* ================================================================
 * PAGINA LOGIN GUARD
 * ================================================================ */
function cs_render_login_guard()
{
    $lg      = cs_lg_settings();
    $sources = cs_lg_ip_sources();
    $my_ip   = cs_lg_client_ip($lg['ip_source']);
    $url     = cs_lg_access_url($lg);
    $off     = defined('CS_LOGIN_GUARD_OFF') && CS_LOGIN_GUARD_OFF;
    $cf_mismatch = !empty($_SERVER['HTTP_CF_CONNECTING_IP']) && $lg['ip_source'] === 'REMOTE_ADDR';
    ?>
    <div class="wrap cs">
        <header class="cs-head">
            <div>
                <a class="cs-back" href="<?php echo esc_url(admin_url('admin.php?page=concrete-security')); ?>">← Controlli</a>
                <h1 class="cs-title">Login Guard</h1>
                <p class="cs-sub">Backoffice e login accessibili solo dagli IP autorizzati o con il link segreto del team.</p>
            </div>
        </header>

        <?php cs_notice(); ?>

        <?php if ($off) : ?>
            <div class="cs-notice cs-notice--warn">Login Guard è disattivato da wp-config.php (<code>CS_LOGIN_GUARD_OFF</code>). Togli la riga per riattivarlo.</div>
        <?php endif; ?>
        <?php if ($cf_mismatch) : ?>
            <div class="cs-notice cs-notice--warn">Il sito sembra dietro Cloudflare: scegli "Cloudflare" come origine dell'IP, altrimenti verrebbe letto l'IP di Cloudflare e non il tuo.</div>
        <?php endif; ?>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="cs_save_lg">
            <?php wp_nonce_field('cs_save_lg'); ?>

            <section class="cs-card">
                <div class="cs-row">
                    <div class="cs-row__check">
                        <span class="cs-dot cs-dot--<?php echo $lg['enabled'] ? 'ok' : 'info'; ?>"></span>
                        <div>
                            <div class="cs-row__label">Attiva Login Guard</div>
                            <p class="cs-row__desc">Chi non è autorizzato vede "Accesso non consentito" su wp-login.php e wp-admin. Il sito pubblico non cambia. Quando lo attivi, il tuo browser viene autorizzato in automatico.</p>
                        </div>
                    </div>
                    <div class="cs-row__action"><?php cs_switch('enabled', (bool) $lg['enabled'], 'Attiva Login Guard'); ?></div>
                </div>
            </section>

            <section class="cs-card">
                <h2 class="cs-card__title"><span class="cs-num">1</span>IP autorizzati</h2>
                <div class="cs-field">
                    <label for="cs-ips">Un IP per riga (es. ufficio). Accettati anche intervalli tipo 192.168.1.0/24. Puoi aggiungere un commento dopo #.</label>
                    <textarea id="cs-ips" name="ips" rows="5" placeholder="93.45.12.34  # ufficio"><?php echo esc_textarea($lg['ips']); ?></textarea>
                    <button type="button" class="cs-btn cs-btn--ghost cs-btn--sm" data-cs-add-ip="<?php echo esc_attr($my_ip); ?>">Aggiungi il mio IP (<?php echo esc_html($my_ip ?: 'non rilevato'); ?>)</button>
                </div>

                <div class="cs-field">
                    <label for="cs-src">Da dove leggere l'IP</label>
                    <select id="cs-src" name="ip_source">
                        <?php foreach ($sources as $k => $label) :
                            $val = cs_lg_client_ip($k); ?>
                            <option value="<?php echo esc_attr($k); ?>" <?php selected($lg['ip_source'], $k); ?>><?php echo esc_html($label . ' → ' . ($val ?: 'vuoto')); ?></option>
                        <?php endforeach; ?>
                    </select>
                    <p class="cs-row__desc">Scegli quella che mostra il tuo vero IP (controllalo su un sito tipo "what is my ip"). Lascia "Standard" se non sai.</p>
                </div>
            </section>

            <section class="cs-card">
                <h2 class="cs-card__title"><span class="cs-num">2</span>Link segreto per lavorare da remoto</h2>
                <p class="cs-row__desc">Chi apre questo link una volta viene autorizzato su quel browser per i giorni indicati, da qualsiasi IP. Mandalo solo al team, mai ai clienti in chiaro.</p>
                <div class="cs-copy">
                    <input type="text" readonly value="<?php echo esc_attr($url); ?>" id="cs-url">
                    <button type="button" class="cs-btn cs-btn--ghost cs-btn--sm" data-cs-copy="#cs-url">Copia</button>
                </div>
                <div class="cs-field cs-field--inline">
                    <label for="cs-days">Validità dell'autorizzazione (giorni)</label>
                    <input id="cs-days" type="number" min="1" max="365" name="days" value="<?php echo (int) $lg['days']; ?>">
                </div>
            </section>

            <div class="cs-savebar">
                <span class="cs-muted">Ti sei chiuso fuori? Aggiungi <code>define('CS_LOGIN_GUARD_OFF', true);</code> nel wp-config.php.</span>
                <button type="submit" class="cs-btn">Salva</button>
            </div>
        </form>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" class="cs-danger" onsubmit="return confirm('Il vecchio link smetterà di funzionare per tutti. Continuare?');">
            <input type="hidden" name="action" value="cs_lg_new_key">
            <?php wp_nonce_field('cs_lg_new_key'); ?>
            <div>
                <strong>Rigenera la chiave</strong>
                <p class="cs-row__desc">Da fare se il link è finito nelle mani sbagliate o se qualcuno lascia il team.</p>
            </div>
            <button type="submit" class="cs-btn cs-btn--danger cs-btn--sm">Rigenera</button>
        </form>
    </div>
    <?php
}
