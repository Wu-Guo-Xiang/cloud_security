// 轻量 5s 增量刷新:用 DOMParser 解析(不会执行 <script> / 事件属性),
// 再从中提取 #events-table 节点做 replaceWith。避免 innerHTML XSS sink。
(function () {
  var container = document.getElementById('events-table');
  if (!container) return;
  var url = container.getAttribute('data-refresh-url');
  if (!url) return;

  var parser = new DOMParser();

  function refresh() {
    fetch(url, { headers: { 'X-Refresh': '1' }, credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        if (!html) return;
        var doc = parser.parseFromString(html, 'text/html');
        var fresh = doc.querySelector('#events-table');
        if (fresh) {
          var adopted = document.adoptNode(fresh);
          container.replaceWith(adopted);
          container = adopted;
        }
      })
      .catch(function () { /* silent */ });
  }
  setInterval(refresh, 5000);
})();
