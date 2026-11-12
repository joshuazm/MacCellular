(function lanLogin() {
  "use strict";

  const form = document.getElementById("login-form");
  const password = document.getElementById("password");
  const submit = document.getElementById("submit");
  const message = document.getElementById("message");

  function nextTarget() {
    const next = new URLSearchParams(location.search).get("next") || "";
    if (next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/lan/")) return next;
    return "/remote/";
  }

  function show(text, ok) {
    message.textContent = text;
    message.classList.toggle("ok", Boolean(ok));
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const value = password.value;
    if (!value) return show("请输入访问密码");
    submit.disabled = true;
    show("正在验证…", true);
    try {
      const response = await fetch("/api/remote/v1/lan/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: value }),
        cache: "no-store",
        credentials: "same-origin",
      });
      const body = await response.json().catch(() => ({}));
      if (response.ok) {
        show("登录成功，正在打开…", true);
        location.replace(nextTarget());
        return;
      }
      if (response.status === 429) show("失败次数过多，请 15 分钟后再试");
      else if (response.status === 401) show("密码不正确");
      else show(body.error || `登录失败（HTTP ${response.status}）`);
    } catch {
      show("无法连接到家中 Mac，请确认手机与 Mac 在同一网络");
    } finally {
      submit.disabled = false;
      password.value = "";
      password.focus();
    }
  });
})();
