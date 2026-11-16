# Sentinela

O Sentinela monitora eventos enviados pela aplicação do cliente; ele não depende de uma sessão de pentest. Cada [Monitor](../../app/Models/Monitor.php) pertence a um usuário e tem chave própria, cujo hash fica no banco. A interface cria, rotaciona e remove monitores e permite configurar webhook. [SentinelController](../../app/Http/Controllers/SentinelController.php).

## Entrada e sequência

1. A aplicação envia `POST /api/sentinela/eventos` com Bearer token do monitor. Há exemplo de SDK para Express em [public/sdk/egide-sentinela.mjs](../../public/sdk/egide-sentinela.mjs). [Rotas API](../../routes/api.php).
2. [IngestController](../../app/Http/Controllers/Api/IngestController.php) autentica monitor e conta ativa, aplica limite de 1 a 100 eventos por lote e retorna `202`.
3. [Ingest](../../app/Sentinel/Ingest.php) valida tipo, IP, status e `subject` como 64 caracteres hexadecimais; remove query/fragment do caminho e persiste os eventos.
4. [Detector](../../app/Sentinel/Detector.php) examina janelas de tempo, cria ou atualiza [Alert](../../app/Models/Alert.php) e despacha [NotifyAlert](../../app/Jobs/NotifyAlert.php) para alertas novos com webhook.

## Regras atuais

| Regra | Condição no código |
| --- | --- |
| Força bruta | 10 falhas do mesmo IP em 5 minutos |
| Credential stuffing | 5 identidades distintas do mesmo IP em 10 minutos |
| Possível tomada de conta | Login aceito após 5 falhas da identidade em 15 minutos |
| Rajada de acesso negado | 20 eventos `access_denied` do mesmo IP em 5 minutos |
| Anomalia | Pelo menos 10 falhas em 5 minutos e valor acima da média mais 3 vezes o maior entre o desvio padrão e 1, calculados sobre janelas de 5 minutos das últimas 24 horas |

Os tipos aceitos estão em [MonitorEvent](../../app/Models/MonitorEvent.php). O alerta é deduplicado por regra, IP, identidade e hora. Um alerta resolvido pode ser reaberto pela interface; consulte o comportamento exato em [Detector](../../app/Sentinel/Detector.php) e [SentinelController](../../app/Http/Controllers/SentinelController.php).

## Dados e cuidados

O identificador de usuário enviado como `subject` deve ser hash HMAC-SHA256, jamais e-mail ou nome. A tela mostra apenas prefixo do hash. O webhook exige HTTPS público e o job de notificação evita reenviar alerta já marcado como notificado. O scheduler remove eventos antigos e alertas resolvidos fora do prazo. [Ingest](../../app/Sentinel/Ingest.php), [Webhook](../../app/Sentinel/Webhook.php), [NotifyAlert](../../app/Jobs/NotifyAlert.php), [routes/console.php](../../routes/console.php).

## Ao estender

Novo evento ou regra requer atualização de tipo/validação, detector, eventual SDK, tela, retenção e testes. Referências: [SentinelTest](../../tests/Feature/SentinelTest.php), [guia de mudanças](../operations/change-guide.md).
