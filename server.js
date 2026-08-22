<!DOCTYPE html>
<html lang="ar" dir="rtl">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>N10 SERVER MENA</title>

  <style>
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
      font-family: Arial, sans-serif;
    }

    body {
      min-height: 100vh;
      background:
        radial-gradient(
          circle at top,
          #123b70 0%,
          #071525 45%,
          #03070d 100%
        );
      color: white;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }

    .container {
      width: 100%;
      max-width: 430px;
      background: rgba(8, 20, 36, 0.94);
      border: 1px solid #168cff;
      border-radius: 24px;
      padding: 30px 22px;
      box-shadow: 0 0 35px rgba(0, 140, 255, 0.25);
      text-align: center;
    }

    .logo {
      width: 95px;
      height: 95px;
      margin: 0 auto 18px;
      border-radius: 24px;
      background: linear-gradient(145deg, #168cff, #0051a8);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 42px;
      font-weight: bold;
      box-shadow: 0 0 25px rgba(22, 140, 255, 0.45);
    }

    .key-icon {
      font-size: 48px;
    }

    h1 {
      color: #42a5ff;
      font-size: 28px;
      margin-bottom: 8px;
    }

    .subtitle {
      color: #a9c9e8;
      font-size: 14px;
      margin-bottom: 28px;
    }

    .card {
      background: rgba(255, 255, 255, 0.04);
      border-radius: 16px;
      padding: 18px;
      margin-bottom: 16px;
    }

    .card h2 {
      color: #42a5ff;
      margin-bottom: 10px;
    }

    .card p {
      color: #c8d9e8;
      font-size: 14px;
      line-height: 1.7;
    }

    .btn {
      display: block;
      width: 100%;
      padding: 14px;
      margin-top: 12px;
      border: none;
      border-radius: 14px;
      background: #168cff;
      color: white;
      text-decoration: none;
      font-weight: bold;
      font-size: 16px;
      cursor: pointer;
    }

    .btn:hover {
      background: #087de8;
    }

    .key-box {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 15px;
    }

    .key-input {
      flex: 1;
      min-width: 0;
      padding: 13px 10px;
      border: 1px solid #168cff;
      border-radius: 12px;
      background: #071525;
      color: white;
      font-size: 13px;
      text-align: center;
      direction: ltr;
    }

    .copy-btn {
      width: auto;
      margin: 0;
      padding: 13px 15px;
      white-space: nowrap;
    }

    .success {
      color: #42a5ff;
      font-weight: bold;
      margin-bottom: 8px;
    }

    .hidden {
      display: none;
    }
  </style>
</head>

<body>

  <div class="container">

    <!-- الشعار -->
    <div class="logo" id="logo">
      N10
    </div>

    <h1>N10 SERVER MENA</h1>

    <p class="subtitle">
      مرحباً بكم في N10 SERVER MENA
    </p>

    <!-- الصفحة الرئيسية -->
    <div id="home">

      <div class="card">
        <h2>أهلاً وسهلاً 👋</h2>

        <p>
          هذا هو الموقع الرسمي لـ N10 SERVER MENA.
        </p>
      </div>

      <div class="card">
        <h2>السيرفر</h2>

        <p>
          للدخول إلى السيرفر، قم بتسجيل الدخول بحساب Discord الخاص بك.
        </p>

        <a
          class="btn"
          href="https://n10-discord-backend-new.onrender.com/auth/discord"
        >
          دخول السيرفر
        </a>
      </div>

    </div>

    <!-- صفحة المفتاح -->
    <div id="keyPage" class="card hidden">

      <div class="success">
        ✅ تم تسجيل الدخول بنجاح
      </div>

      <h2>🔑 مفتاح التفعيل</h2>

      <p>
        هذا هو مفتاح التفعيل الخاص بك:
      </p>

      <div class="key-box">

        <input
          id="accessKey"
          class="key-input"
          type="text"
          readonly
        >

        <button
          class="btn copy-btn"
          onclick="copyKey()"
        >
          📋 نسخ
        </button>

      </div>

<p
        id="copyMessage"
        style="margin-top:12px;"
      ></p>

    </div>

  </div>

  <script>

    /* قراءة مفتاح التفعيل من الرابط */
    const params = new URLSearchParams(window.location.search);
    const accessKey = params.get("accessKey");

    /* إذا كان هناك مفتاح، نعرض صفحة المفتاح */
    if (accessKey) {

      document
        .getElementById("home")
        .classList
        .add("hidden");

      document
        .getElementById("keyPage")
        .classList
        .remove("hidden");

      /* تغيير الشعار إلى مفتاح */
      document
        .getElementById("logo")
        .innerHTML =
        '<span class="key-icon">🔑</span>';

      /* وضع المفتاح داخل الخانة */
      document
        .getElementById("accessKey")
        .value = accessKey;
    }

    /* نسخ المفتاح */
    async function copyKey() {

      const key =
        document
          .getElementById("accessKey")
          .value;

      try {

        await navigator.clipboard.writeText(key);

        document
          .getElementById("copyMessage")
          .textContent =
          "✅ تم نسخ المفتاح";

      } catch (error) {

        const input =
          document
            .getElementById("accessKey");

        input.select();

        document.execCommand("copy");

        document
          .getElementById("copyMessage")
          .textContent =
          "✅ تم نسخ المفتاح";
      }
    }

  </script>

</body>
</html>
