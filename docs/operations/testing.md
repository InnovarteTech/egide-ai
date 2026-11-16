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

## Encontre o teste do comportamento

| Mudança | Testes iniciais |
| --- | --- |
| Autorização, proxy e tipo de ambiente | [ScopeTest](../../tests/Unit/ScopeTest.php), [ScopeGateTest](../../tests/Feature/ScopeGateTest.php), [test_policy.py](../../tests/runner/test_policy.py) |
| Sessão, cobertura e laboratório | [RunScanOraclesTest](../../tests/Feature/RunScanOraclesTest.php), [AgenticLabTest](../../tests/Feature/AgenticLabTest.php), [test_lab.py](../../tests/runner/test_lab.py) |
| Planejamento, payload e provas | [PlannerTest](../../tests/Feature/PlannerTest.php), [PayloadOraclesTest](../../tests/Unit/PayloadOraclesTest.php), [HunterTest](../../tests/Unit/HunterTest.php) |
| Sentinela | [SentinelTest](../../tests/Feature/SentinelTest.php) |
| API, CI e automação | [AutomationTest](../../tests/Feature/AutomationTest.php), [CiGateTest](../../tests/Feature/CiGateTest.php) |
| Administração | [AdminTest](../../tests/Feature/AdminTest.php) |

## Evidência suficiente para um PR

Rode primeiro os testes do fluxo alterado. Para nova técnica de detecção, verifique tanto a variante vulnerável quanto a corrigida e um caso inconclusivo quando aplicável. Para mudança no contrato PHP/runner, verifique ambos os lados e, se a alteração toca navegação/proxy real, rode o fluxo no laboratório Docker. Registre comandos executados e qualquer limite do ambiente no PR. [guia de mudanças](change-guide.md).
