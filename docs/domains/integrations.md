# Integrações: API, CI, agenda e webhooks

Estas entradas reutilizam o mesmo modelo de ambiente e sessão do console. As rotas estão em [routes/api.php](../../routes/api.php) e [routes/web.php](../../routes/web.php).

## API v1 e CI

Um token `escapi_…` é emitido em Configurações, mostrado uma vez e armazenado como hash. [AuthenticateApiToken](../../app/Http/Middleware/AuthenticateApiToken.php) autentica e associa o usuário à requisição. Os endpoints são `GET /api/v1/ativos`, `POST /api/v1/sessoes` e `GET /api/v1/sessoes/{scan}`. O POST recebe `ativo` e `orcamento` opcional de 10 a 180; a sessão entra na fila e retorna `202`. [IntegrationController](../../app/Http/Controllers/IntegrationController.php), [ScanApiController](../../app/Http/Controllers/Api/ScanApiController.php).

`portao.passou` é calculado em [ScanApiController](../../app/Http/Controllers/Api/ScanApiController.php): sessão concluída e nenhum achado `critical`/`high`. `portao.pendente` indica sessão em andamento. Há um [workflow de exemplo](../../public/ci/egide-github-action.yml). A flag `regressao` é exposta pela API, mas não entra hoje na expressão de `portao.passou`; confirmar a regra de produto na [descoberta](../discovery/2026-11-16-product-architecture-and-docs-plan.md).

## Agenda

O usuário configura `off`, `daily` ou `weekly` em ambiente verificado. [routes/console.php](../../routes/console.php) roda `egide:agendadas` a cada 15 minutos e [Launcher](../../app/Security/Launcher.php) cria a sessão. Em falha de disparo, agenda nova tentativa após uma hora. [IntegrationController](../../app/Http/Controllers/IntegrationController.php).

## Webhooks

O webhook do workspace recebe conclusão de sessão, contagem de achados, risco, regressão e URL de relatório. O webhook de cada monitor recebe alertas do Sentinela. Ambos exigem URL HTTPS pública por [Webhook](../../app/Sentinel/Webhook.php). O envio ocorre em jobs com tentativas e backoff: [NotifyScan](../../app/Jobs/NotifyScan.php) e [NotifyAlert](../../app/Jobs/NotifyAlert.php). O callback de prova fora de banda em `/api/colaborador/{token}` tem finalidade distinta: confirmar SSRF, não notificar o usuário. [CollaboratorController](../../app/Http/Controllers/Api/CollaboratorController.php).

## Ao estender

Mantenha isolamento por usuário e contrato do portão. Mudanças no retorno da API exigem revisar clientes/CI; mudanças em webhook devem preservar validação de destino e não expor segredos. Testes de referência: [AutomationTest](../../tests/Feature/AutomationTest.php), [CiGateTest](../../tests/Feature/CiGateTest.php), [CollaboratorTest](../../tests/Feature/CollaboratorTest.php).
