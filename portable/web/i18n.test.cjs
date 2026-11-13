const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const i18n = require('./i18n.js');
const locales = require('./locales.json');
i18n.configure(locales);

test('Russian and English cover the same keys and preserve placeholders', () => {
  assert.deepEqual(Object.keys(locales.ru).sort(), Object.keys(locales.en).sort());
  const placeholders = (text) => (text.match(/\{[a-zA-Z]+\}/g) || []).sort();
  for (const key of Object.keys(locales.ru)) {
    assert.ok(locales.ru[key].trim(), key);
    assert.ok(locales.en[key].trim(), key);
    assert.deepEqual(placeholders(locales.en[key]), placeholders(locales.ru[key]), key);
    if (key !== 'Русский') assert.doesNotMatch(locales.en[key], /[А-Яа-яЁё]/, key);
  }
});

test('all panel copy and explicit translation calls are covered', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const script = fs.readFileSync(path.join(__dirname, 'panel.js'), 'utf8');
  const keys = [...script.matchAll(/\bt\(("(?:[^"\\]|\\.)*")/g)].map((match) => JSON.parse(match[1]).trim());
  for (const match of html.matchAll(/>([^<>]+)<|(?:placeholder|aria-label|title)="([^"]+)"/g)) {
    const text = (match[1] || match[2]).trim();
    if (/[А-Яа-яЁё]/.test(text)) keys.push(text);
  }
  for (const key of keys) assert.ok(Object.hasOwn(locales.en, key), `Missing translation: ${key}`);
});

test('system locale defaults to Russian only for Russian locales', () => {
  assert.equal(i18n.choose('system', 'ru-RU'), 'ru');
  assert.equal(i18n.choose('system', 'en-US'), 'en');
  assert.equal(i18n.choose('system', 'de-DE'), 'en');
  assert.equal(i18n.choose('en', 'ru-RU'), 'en');
  assert.equal(i18n.choose('ru', 'en-US'), 'ru');
});

test('backend reasons and errors translate without modifying user values', () => {
  i18n.choose('ru');
  assert.equal(i18n.message('IPv4 uses Wi-Fi instead of wg0'), 'IPv4 использует Wi-Fi вместо wg0');
  assert.equal(i18n.message('api.example.com did not confirm its service route: no route'), 'Сервис api.example.com не подтвердил маршрут: Маршрут не найден');
  assert.equal(i18n.message('Invalid unknown provider error /home/Пользователь/app'), 'Invalid unknown provider error /home/Пользователь/app');
  i18n.choose('en');
  assert.equal(i18n.message('Не удалось приостановить приложение.'), 'Could not pause the app.');
  assert.equal(i18n.translate(' Удалить '), ' Remove ');
  assert.equal(i18n.translate('Started {value}', { value: 'My $& {other} tool' }), 'Started My $& {other} tool');
});

test('journals preserve dates and application names while translating event data', () => {
  i18n.choose('en');
  assert.equal(i18n.journal('2026-11-13T12:00:00Z На паузе · Моя программа'), '2026-11-13T12:00:00Z Paused · Моя программа');
  assert.equal(i18n.journal('2026-11-13T12:00:00Z IP разрешён · 203.0.113.10'), '2026-11-13T12:00:00Z IP allowed · 203.0.113.10');
  i18n.choose('ru');
  assert.equal(i18n.journal('2026-11-13T12:00:00Z paused My tool · network changed'), '2026-11-13T12:00:00Z Приостановлено My tool · сеть изменилась');
  assert.equal(i18n.journal('2026-11-13T12:00:00Z Проверка утечек · DNS outside'), '2026-11-13T12:00:00Z Проверка утечек · DNS вне VPN');
});
