# MySafeAI для браузера

Дополнение защищает выбранные AI-сайты и свои домены в Chrome, Edge, Brave и Firefox на платформах, где работает настольный MySafeAI. Оно не меняет системный прокси, VPN или firewall. Состояние защиты передаётся через Native Messaging без локального HTTP-сервера. Сайты, история, содержимое запросов и cookies не передаются приложению.

Инструкция установки и подключения: [docs/browser-extension.md](../docs/browser-extension.md).

## Поведение

- По умолчанию защищены ChatGPT/OpenAI, Claude/Anthropic, Cursor и Gemini/AI Studio. В popup можно отдельно отключить любую группу.
- В разделе «Свои сайты» можно добавить до 50 публичных доменов. Поддомены включаются автоматически. Принимается домен или HTTPS-адрес без пути, порта, параметров и логина. IDN переводится в ASCII/punycode. IP-адреса, локальные имена и маски не принимаются. Свои домены хранятся локально; их блокирующие правила постоянны, разрешения — только на время браузерной сессии.
- Язык интерфейса выбирается автоматически: русский для `ru-*`, английский для остальных языков. Выбор System / Русский / English можно сохранить в popup или на странице паузы.
- Статические правила блокируют запросы к защищённым доменам до ответа приложения. Подтверждённое подключение или явная пауза/отключение защиты в MySafeAI добавляет временные разрешающие правила браузерной сессии.
- Расширение опрашивает native host каждую секунду. Потеря связи, некорректный ответ или отсутствие свежего ответа более 2,5 секунд снимают разрешение. Native host дополнительно проверяет свежесть снимка состояния приложения.
- При блокировке открытые вкладки выбранных AI-сайтов переходят на локальную страницу паузы. Это завершает их соединения и может потерять несохранённый ввод. URL остаётся только в `storage.session` браузера, удаляется при закрытии вкладки или возврате на сайт и не отправляется native host.
- Возврат на сайт требует явного нажатия и нового подтверждения. Остальные сайты не блокируются. Адреса API выбранных сервисов блокируются из любого источника — поэтому интеграция AI на стороннем сайте тоже может перестать работать.

## Границы защиты

Это фильтрация запросов браузера, **не системная блокировка пакетов**. Она не защищает другие программы, WebRTC/произвольный UDP, неизвестные дополнительные домены сервиса или уже установленные потоки из сторонних вкладок. DNR видит новые HTTP-запросы и установление WebSocket, но не закрывает произвольный существующий поток. Для открытой AI-вкладки используется переход на страницу паузы; соединения фоновых service workers и сетевые буферы не являются гарантированной зоной контроля.

В Chromium открытый `connectNative` удерживает worker расширения активным. При его нормальном перезапуске сначала удаляются старые разрешения. Однако API DNR не имеет TTL: **авария worker при продолжающем работать браузере может оставить разрешение до следующего запуска worker**. Alarm используется для повторного запуска, но браузер может задержать его. Перезапуск браузера или обновление дополнения сбрасывают session-правила. Расширение не обещает нулевое окно утечки и не заменяет kill switch VPN-клиента.

Выключение/удаление расширения снимает его правила. Приватные окна защищаются только если пользователь отдельно разрешил работу дополнения в них. Safari в этом выпуске не поддерживается.

## Custom domains and English UI

Use **Your sites** in the popup to add or remove up to 50 public domains. Subdomains are included automatically. Enter a domain or an HTTPS origin without credentials, a path, port or query. International domain names are stored as ASCII/punycode. IP addresses, local hostnames and wildcards are rejected. Domains and saved tab URLs stay in the browser and are never sent to the native host.

Custom domains get persistent DNR **block** rules before temporary session **allow** rules can be applied. A disabled preset group cannot override a custom block. Removing a custom domain removes only this extension's reserved rule IDs. Static preset blocks and persisted custom blocks remain when a native connection is lost; a worker restart first clears session permissions.

Every popup/pause-page label, error, accessibility label and badge supports English and Russian. The default follows the browser language (`ru-*` → Russian, otherwise English); an explicit language choice is saved locally. Chromium/Edge/Brave and Firefox **140+** desktop are supported. Safari and mobile native messaging are not included.

This is browser request filtering, not an operating-system packet firewall. WebRTC, existing streams from unrelated tabs, unknown service domains, and service-worker network buffers are outside its guarantee. A browser worker crash can leave DNR session allows until the worker restarts; the browser does not provide a rule TTL. Visiting the local pause page closes the selected tab's connections and can lose unsaved input. Restore is always explicit.

## Разработка

```sh
node --test browser-extension/tests/*.test.cjs
node browser-extension/package.mjs dist/browser-extension
```

Готовые каталоги: `dist/browser-extension/chromium` и `dist/browser-extension/firefox`. Второй содержит отдельный Firefox manifest. Chrome ID закреплён публичным ключом: `akehebbcjgcamdjgjpmhepmgjjlldbik`. Приватного ключа в репозитории нет. Firefox ID: `mysafeai@in-devp`. Native host: `app.mysafeai.browser`.

Проверенные первичные спецификации:

- [Native Messaging Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [Жизненный цикл worker](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [DNR, время жизни правил](https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest)
- [Firefox background scripts](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background)
- [Firefox DNR session rules](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/declarativeNetRequest/updateSessionRules)
