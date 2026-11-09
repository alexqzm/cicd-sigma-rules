# KUMA

В KUMA правила Sigma, по документации KUMA 4.0, переводятся конвертером Sigma: выбирается
бэкенд `kuma` и формат `default`, поле конвейера остаётся пустым, а на вкладку `pipeline.yaml`
вставляется словарь полей, адаптированный для pySigma. Результат — условие `WHERE` SQL-запроса,
которое используется как запрос поиска или фильтр
([Preparing a Sigma rule](https://support.kaspersky.com/kuma/4.0/en-US/302128.htm)). На странице
[Examples of supported Sigma rule conversions](https://support.kaspersky.com/kuma/4.0/en-US/301637.htm)
показаны соответствия правил Sigma фильтрам и правилам корреляции KUMA (поддержка корреляций —
частичная) и сопоставления полей нормализаторами для событий Windows и Sysmon.

Публичного бэкенда pySigma для KUMA в PyPI нет (проверено 09.11.2026), поэтому запросов KUMA в
`conversions/` нет и в KUMA правила этого репозитория не проверялись.

## Журнал аудита GitHub в KUMA

Чтобы правила `rules/github/` работали в KUMA, нужны нормализатор событий журнала аудита GitHub
(JSON) и тот же словарь полей в конвертере. Предложение автора — поля нормализованного события
KUMA из [модели данных KUMA 4.0](https://support.kaspersky.com/kuma/4.0/en-US/217941.htm):

| Поле журнала аудита GitHub | Поле KUMA | Метка поля |
|---|---|---|
| — | `DeviceVendor` = `GitHub` | |
| — | `DeviceProduct` = `Audit log` | |
| `action` | `DeviceAction` (строка до 63 символов; самое длинное событие в правилах — 49) | |
| `actor` | `SourceUserName` | |
| `repo` | `DeviceCustomString1` | `repo` |
| `event` | `DeviceCustomString2` | `event` |
| `public_repo` | `DeviceCustomString3` | `public_repo` |
| `runner_group_allow_public` | `DeviceCustomString4` | `runner_group_allow_public` |
| `org` | `DeviceCustomString5` | `org` |
| остальные поля | `Extra` | |

Тот же словарь в формате конвейера pySigma —
[`pipelines/kuma-github-audit.yml`](../pipelines/kuma-github-audit.yml): условие на
`DeviceVendor` и `DeviceProduct` и переименование полей правил GitHub. Тест
`tests/test_pipelines.py` проверяет, что pySigma загружает конвейер, переименовывает поля всех
правил GitHub, включая поле группировки корреляции, и не трогает правила `process_creation`.

Поля `DeviceCustomString` в KUMA строковые, а в правилах `public_repo: true` — логическое
значение; преобразование `convert_type` в pySigma 1.5.1 переводит в строки только числа. Проверьте,
что условие на эти поля после конвертации сравнивает со строкой `'true'`.

Корреляцию `github_pull_request_target_then_workflow_dispatch` придётся собрать как правило
корреляции KUMA вручную; соответствие семантике Sigma стоит проверить на сценариях A–F из
[`correlation.md`](correlation.md).

## Создание процессов в Linux

Сопоставление полей `process_creation` зависит от нормализатора источника (Sysmon for Linux,
auditd, EDR) в вашей KUMA; примеры для событий Sysmon — на странице примеров конвертации.
Учтите регистр: подстроки в правилах Sigma сравниваются без учёта регистра.
