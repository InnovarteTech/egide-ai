# Testes e evidências

O projeto divide os testes entre **PHPUnit/Laravel** em `tests/Unit` e `tests/Feature`, e **unittest Python** em `tests/runner`. Os testes de fluxo usam banco e fakes; o caminho real com Firefox e mitmproxy exige runners Docker. [phpunit.xml](../../phpunit.xml), [tests](../../tests), [README](../../README.md).

## Comandos

Na raiz do repositório, com dependências instaladas:

```bash
php artisan test
python3 -m unittest discover -s tests/runner
npm run build
```

Em Windows PowerShell, `python` pode substituir `python3` conforme a instalação. Os testes Python importam módulos do runner e podem exigir `mitmproxy` no ambiente; prefira executá-los em WSL/Linux ou no ambiente Python preparado para o runner. Se `vendor/` ou `node_modules/` não existem, instale as dependências antes dos comandos. [composer.json](../../composer.json), [package.json](../../package.json), [runner/Dockerfile](../../runner/Dockerfile).

O [microsite público](../../landing/README.md) é separado do aplicativo e usa somente Node para gerar e verificar as versões EN/PT:

```bash
node landing/build.mjs
node landing/check.mjs
```

Com sessões concluídas das duas variantes do laboratório, `php artisan egide:bench --last=10 --json` mede detecção, falsos positivos e custo por sessão e por achado; `--sessao=<id>` (repetível) limita o relatório a sessões específicas. O consumo por fase aparece no evento e no relatório da sessão. [EgideBench](../../app/Console/Commands/EgideBench.php), [RunScan](../../app/Jobs/RunScan.php).

## Benchmark executado

Com Redis, Horizon e os runners Docker no ar (`bin/egide`), `php artisan egide:bench:run --pares=3 --orcamento=300 --saida=bench.json` enfileira pares de sessões (`laboratory` na variante vulnerável e `retest` na corrigida) em nome do primeiro administrador, espera todas terminarem e grava o relatório de `egide:bench` só dessas sessões. Sem `--agente`, usa o roteiro determinístico do laboratório (`provider=lab`, sem custo de IA); com `--agente`, usa o motor configurado no Super admin. O orçamento padrão do console (80 requisições) cobre só as verificações de autorização e configuração; use 300 para a bateria completa de injeção. Sessões que terminam como `failed` ou `cancelled` são avisadas e ficam fora do relatório. [EgideBenchRun](../../app/Console/Commands/EgideBenchRun.php).

`egide:bench --gabarito=tests/fixtures/lab-gabarito.json` compara a união das classes detectadas com a lista fixa de falhas plantadas e informa cobertura, faltantes e nunca testadas — também dentro do relatório JSON (`gabarito`). `--min=0.9` reprova o comando quando a cobertura fica abaixo da fração; `egide:bench:run` repassa as duas opções e usa o gabarito padrão do repositório quando existir.

`egide:bench:run --provedores=lab,anthropic,openai` roda a matriz de provedores: os pares de cada provedor são medidos em relatórios separados na chave `matriz` do JSON. Provedores hospedados precisam de chave: a do Super admin vale para o provedor configurado lá; para os demais use `EGIDE_BENCH_<PROVEDOR>_KEY` (ex.: `EGIDE_BENCH_OPENAI_KEY`). `--modelo=` troca o modelo dos hospedados. `egide:bench:run --concorrencia=N` lança N sessões simultâneas da variante vulnerável e mede o tempo de fila (`fila_s`, média e máximo) no lugar do relatório de detecção.

## Carga do Sentinela

[scripts/bench/sentinela-carga.js](../../scripts/bench/sentinela-carga.js) é um roteiro [k6](https://k6.io) para `POST /api/sentinela/eventos`. Crie monitores, passe as chaves em `KEYS` e rode:

```bash
docker run --rm --network host -v "$PWD/scripts/bench:/bench" grafana/k6 run \
  -e BASE=http://127.0.0.1:8187 -e KEYS=esc_a,esc_b -e RATE=15 -e BATCH=50 /bench/sentinela-carga.js
```

A rota limita 600 lotes por minuto por chave e IP e 1.200 por IP; acima disso o `429` é esperado e aparece na métrica `lotes_limitados_429`. `php artisan serve` atende uma requisição por vez, então use o compose de produção (Apache e PostgreSQL) para medir capacidade.

## Encontre o teste do comportamento

| Mudança | Testes iniciais |
| --- | --- |
| Autorização, proxy e tipo de ambiente | [ScopeTest](../../tests/Unit/ScopeTest.php), [ScopeGateTest](../../tests/Feature/ScopeGateTest.php), [test_policy.py](../../tests/runner/test_policy.py), [test_policy_fuzz.py](../../tests/runner/test_policy_fuzz.py) |
| Sessão, cobertura e laboratório | [RunScanOraclesTest](../../tests/Feature/RunScanOraclesTest.php), [AgenticLabTest](../../tests/Feature/AgenticLabTest.php), [test_lab.py](../../tests/runner/test_lab.py) |
| Planejamento, payload e provas | [PlannerTest](../../tests/Feature/PlannerTest.php), [PayloadOraclesTest](../../tests/Unit/PayloadOraclesTest.php), [HunterTest](../../tests/Unit/HunterTest.php) |
| Segurança por ambiente e parada automática | [SafetyIntegrationTest](../../tests/Feature/SafetyIntegrationTest.php), [TargetSafetySettingsTest](../../tests/Feature/TargetSafetySettingsTest.php), [test_policy.py](../../tests/runner/test_policy.py), [test_runner_extras.py](../../tests/runner/test_runner_extras.py) |
| Superfície importada | [SurfaceControllerTest](../../tests/Feature/SurfaceControllerTest.php), [SurfaceImportTest](../../tests/Unit/SurfaceImportTest.php) |
| Achados, observações, CVSS e hipóteses | [FindingTrackTest](../../tests/Feature/FindingTrackTest.php), [ObservationTrackTest](../../tests/Feature/ObservationTrackTest.php), [SeverityTest](../../tests/Unit/SeverityTest.php), [HypothesisModelTest](../../tests/Feature/HypothesisModelTest.php) |
| Orçamento por fase e benchmark | [BudgetLedgerTest](../../tests/Unit/BudgetLedgerTest.php), [EgideBenchTest](../../tests/Feature/EgideBenchTest.php) |
| Sentinela | [SentinelTest](../../tests/Feature/SentinelTest.php) |
| API, CI e automação | [AutomationTest](../../tests/Feature/AutomationTest.php), [CiGateTest](../../tests/Feature/CiGateTest.php) |
| Administração | [AdminTest](../../tests/Feature/AdminTest.php) |

## Evidência suficiente para um PR

Rode primeiro os testes do fluxo alterado. Para nova técnica de detecção, verifique tanto a variante vulnerável quanto a corrigida e um caso inconclusivo quando aplicável. Para mudança no contrato PHP/runner, verifique ambos os lados e, se a alteração toca navegação/proxy real, rode o fluxo no laboratório Docker. Registre comandos executados e qualquer limite do ambiente no PR. [guia de mudanças](change-guide.md).
