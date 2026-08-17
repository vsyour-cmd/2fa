(function () {
  try {
    var raw = localStorage.getItem('2fa_settings_v3');
    var saved = raw ? JSON.parse(raw) : {};
    var preference = ['system', 'light', 'dark'].includes(saved && saved.theme)
      ? saved.theme
      : 'system';
    var prefersDark = preference === 'system'
      && typeof matchMedia === 'function'
      && matchMedia('(prefers-color-scheme: dark)').matches;

    if (preference === 'dark' || prefersDark) {
      document.documentElement.dataset.theme = 'dark';
      document.documentElement.style.colorScheme = 'dark';
      var themeColor = document.querySelector('meta[name="theme-color"]');
      if (themeColor) themeColor.content = '#070b14';
    }
  } catch (_error) {
    // Theme boot must never block the application shell.
  }
}());
