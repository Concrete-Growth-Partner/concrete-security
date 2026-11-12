(function () {
  // "Aggiungi il mio IP"
  document.querySelectorAll('[data-cs-add-ip]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var ip = btn.getAttribute('data-cs-add-ip');
      var ta = document.getElementById('cs-ips');
      if (!ip || !ta) return;
      var lines = ta.value.split('\n').map(function (l) { return l.split('#')[0].trim(); });
      if (lines.indexOf(ip) !== -1) return;
      ta.value = (ta.value.trim() ? ta.value.trim() + '\n' : '') + ip;
    });
  });

  // "Copia"
  document.querySelectorAll('[data-cs-copy]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = document.querySelector(btn.getAttribute('data-cs-copy'));
      if (!input) return;
      input.select();
      var done = function () {
        var t = btn.textContent;
        btn.textContent = 'Copiato';
        setTimeout(function () { btn.textContent = t; }, 1500);
      };
      if (navigator.clipboard) {
        navigator.clipboard.writeText(input.value).then(done, function () { document.execCommand('copy'); done(); });
      } else {
        document.execCommand('copy');
        done();
      }
    });
  });

  // Bottone in caricamento
  document.querySelectorAll('[data-cs-loading]').forEach(function (btn) {
    btn.form && btn.form.addEventListener('submit', function () {
      btn.disabled = true;
      btn.textContent = btn.getAttribute('data-cs-loading');
    });
  });
})();
