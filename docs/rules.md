# Правила

Сгенерировано `python -m tools.table` из правил, `mappings/mappings.yml`, эталонных событий
и `conversions/`; вручную не правится. Сопоставления с инцидентами, OWASP и ГОСТ — оценка
автора; теги ATT&CK — по версии ATT&CK 20.1.

| Правило | Уровень | Источник | ATT&CK | Инциденты (атлас) | OWASP CI/CD | ГОСТ Р 56939-2024 | Эталонные события (match / nomatch) | Запросы |
|---|---|---|---|---|---|---|---|---|
| [GitHub Actions Allowed Actions Policy Changed](../rules/github/audit/github_actions_allowed_actions_policy_changed.yml) | низкий | github/audit | [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools | [tj-actions-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/tj-actions-2025.yaml) | CICD-SEC-3, CICD-SEC-8 | 5.12, 5.17 | 2 / 3 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [GitHub Actions Fork Pull Request Workflow Policy Changed](../rules/github/audit/github_actions_fork_pr_policy_changed.yml) | низкий | github/audit | [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools | — | CICD-SEC-4, CICD-SEC-1 | 5.13, 5.14 | 6 / 2 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [GitHub Actions Workflow Execution Protection Violation](../rules/github/audit/github_actions_policy_violation.yml) | средний | github/audit | [T1677](https://attack.mitre.org/techniques/T1677/) Poisoned Pipeline Execution | [nx-s1ngularity-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/nx-s1ngularity-2025.yaml), [tanstack-2026](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/tanstack-2026.yaml) | CICD-SEC-4, CICD-SEC-1 | 5.12, 5.13 | 2 / 3 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [GitHub Actions GITHUB_TOKEN Permission Policy Changed](../rules/github/audit/github_actions_token_policy_changed.yml) | низкий | github/audit | [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools | [nx-s1ngularity-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/nx-s1ngularity-2025.yaml) | CICD-SEC-5 | 5.14, 5.15 | 4 / 2 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [GitHub Branch Protection Requirement Overridden](../rules/github/audit/github_branch_protection_overridden.yml) | средний | github/audit | [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools | — | CICD-SEC-1 | 5.9, 5.14 | 1 / 2 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [GitHub Immutable Releases Disabled or Policy Changed](../rules/github/audit/github_immutable_releases_disabled.yml) | средний | github/audit | [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools | [tj-actions-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/tj-actions-2025.yaml) | CICD-SEC-9 | 5.20, 5.21 | 2 / 2 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [GitHub Branch Protection, Ruleset or Deployment Protection Rule Removed](../rules/github/audit/github_protection_removed.yml) | средний | github/audit | [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools | — | CICD-SEC-1 | 5.4, 5.14 | 3 / 3 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [GitHub Actions Run Triggered by pull_request_target in Public Repository](../rules/github/audit/github_pull_request_target_run_public_repo.yml) | низкий | github/audit | [T1677](https://attack.mitre.org/techniques/T1677/) Poisoned Pipeline Execution | [nx-s1ngularity-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/nx-s1ngularity-2025.yaml), [tanstack-2026](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/tanstack-2026.yaml) | CICD-SEC-4 | 5.13, 5.15 | 1 / 4 | opensearch, elasticsearch, elasticsearch-eql*, splunk |
| [GitHub Runner Group Opened to Public Repositories](../rules/github/audit/github_runner_group_allows_public_repos.yml) | средний | github/audit | [T1685](https://attack.mitre.org/techniques/T1685/) Disable or Modify Tools | — | CICD-SEC-7, CICD-SEC-4 | 5.13 | 2 / 3 | opensearch, elasticsearch, elasticsearch-eql*, splunk |
| [GitHub Self-Hosted Runner Registered to Public Repository](../rules/github/audit/github_self_hosted_runner_registered_public_repo.yml) | средний | github/audit | [T1677](https://attack.mitre.org/techniques/T1677/) Poisoned Pipeline Execution | — | CICD-SEC-4, CICD-SEC-7 | 5.13 | 1 / 3 | opensearch, elasticsearch, elasticsearch-eql*, splunk |
| [GitHub Actions pull_request_target Run Followed by workflow_dispatch Run](../rules/github/correlation/github_pull_request_target_then_workflow_dispatch.yml) | низкий | github/audit, корреляция | [T1677](https://attack.mitre.org/techniques/T1677/) Poisoned Pipeline Execution | [nx-s1ngularity-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/nx-s1ngularity-2025.yaml) | CICD-SEC-4, CICD-SEC-5 | 5.13, 5.15, 5.20 | 5 / 8 | elasticsearch-eql* |
| [AI Coding CLI Launched With Permission Bypass Flag](../rules/linux/process_creation/proc_creation_lnx_ai_cli_permission_bypass.yml) | низкий | linux/process_creation | [T1204.005](https://attack.mitre.org/techniques/T1204/005/) Malicious Library<br>[T1552.001](https://attack.mitre.org/techniques/T1552/001/) Credentials In Files | [nx-s1ngularity-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/nx-s1ngularity-2025.yaml) | CICD-SEC-3 | 5.13, 5.17 | 3 / 3 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [Node.js Process Launching AI Coding CLI With Permission Bypass Flag](../rules/linux/process_creation/proc_creation_lnx_node_ai_cli_permission_bypass.yml) | высокий | linux/process_creation | [T1204.005](https://attack.mitre.org/techniques/T1204/005/) Malicious Library<br>[T1552.001](https://attack.mitre.org/techniques/T1552/001/) Credentials In Files | [nx-s1ngularity-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/nx-s1ngularity-2025.yaml) | CICD-SEC-3 | 5.16, 5.17 | 3 / 4 | opensearch, elasticsearch, elasticsearch-eql, splunk |
| [Search for GitHub Actions Runner Secret Markers](../rules/linux/process_creation/proc_creation_lnx_runner_secret_marker_search.yml) | высокий | linux/process_creation | [T1003.007](https://attack.mitre.org/techniques/T1003/007/) Proc Filesystem | [tj-actions-2025](https://github.com/alexqzm/cps-supply-chain-atlas/blob/main/data/records/tj-actions-2025.yaml) | CICD-SEC-3, CICD-SEC-6 | 5.13, 5.15 | 4 / 4 | opensearch*, elasticsearch*, elasticsearch-eql, splunk |

\* Запрос этой цели расходится с эталонными событиями в движке SIEM (дефект бэкенда или
зависимость от хранения строк) — см. [известные расхождения](../conversions/README.md#проверка-в-движках).

## OWASP Top 10 CI/CD Security Risks

- **CICD-SEC-1** — Insufficient Flow Control Mechanisms
- **CICD-SEC-3** — Dependency Chain Abuse
- **CICD-SEC-4** — Poisoned Pipeline Execution (PPE)
- **CICD-SEC-5** — Insufficient PBAC (Pipeline-Based Access Controls)
- **CICD-SEC-6** — Insufficient Credential Hygiene
- **CICD-SEC-7** — Insecure System Configuration
- **CICD-SEC-8** — Ungoverned Usage of 3rd Party Services
- **CICD-SEC-9** — Improper Artifact Integrity Validation

## Процессы ГОСТ Р 56939-2024

- **5.4** — Управление конфигурацией программного обеспечения
- **5.9** — Экспертиза исходного кода
- **5.12** — Использование безопасной системы сборки программного обеспечения
- **5.13** — Обеспечение безопасности сборочной среды программного обеспечения
- **5.14** — Управление доступом и контроль целостности кода при разработке программного обеспечения
- **5.15** — Обеспечение безопасности используемых секретов
- **5.16** — Использование инструментов композиционного анализа
- **5.17** — Проверка кода на предмет внедрения вредоносного программного обеспечения через цепочки поставок
- **5.20** — Обеспечение безопасности при выпуске готовой к эксплуатации версии программного обеспечения
- **5.21** — Безопасная поставка программного обеспечения пользователям
