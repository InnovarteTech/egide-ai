<?php

namespace Tests\Unit;

use App\Security\ApiOracles;
use PHPUnit\Framework\TestCase;

class ApiOraclesTest extends TestCase
{
    private function response(int $status, array $fields = [], bool $blocked = false): array
    {
        return ['status' => $status, 'fields' => $fields, 'blocked' => $blocked];
    }

    public function test_mass_assignment_confirms_only_when_the_forged_field_persists(): void
    {
        $sentinel = 'EGIDE-MA-abcdef';
        $write = $this->response(200);
        $after = $this->response(200, [['key' => 'role', 'value' => $sentinel]]);

        $falha = ApiOracles::massAssignmentAssess('/api/perfil', 'role', $sentinel, $write, $after);
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('critical', $falha['finding']['severity']);
        $this->assertSame('OWASP API3:2023 · CWE-915', $falha['finding']['evidence']['reference']);
        $this->assertSame('role', $falha['finding']['evidence']['field']);

        // Campo não persistiu → protegido.
        $protegido = ApiOracles::massAssignmentAssess('/api/perfil', 'role', $sentinel, $write, $this->response(200, [['key' => 'role', 'value' => 'user']]));
        $this->assertSame('protegido', $protegido['verdict']);

        // Escrita bloqueada ou re-fetch falhou → não testado (sem falso-positivo nem falso-protegido).
        $this->assertSame('nao_testado', ApiOracles::massAssignmentAssess('/api/perfil', 'role', $sentinel, $this->response(0), $after)['verdict']);
        $this->assertSame('nao_testado', ApiOracles::massAssignmentAssess('/api/perfil', 'role', $sentinel, $this->response(200, [], true), $after)['verdict']);
        $this->assertSame('nao_testado', ApiOracles::massAssignmentAssess('/api/perfil', 'role', $sentinel, $write, $this->response(500))['verdict']);
    }

    public function test_prototype_pollution_confirms_when_marker_surfaces_on_an_unrelated_response(): void
    {
        $marker = 'egidePP7f3a1c';
        // Depois de poluir via __proto__, uma resposta não relacionada passa a carregar a propriedade poluída.
        $falha = ApiOracles::prototypePollutionAssess('/api/config', $marker, '{"theme":"dark","egidePoluido":"egidePP7f3a1c"}');
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('high', $falha['finding']['severity']);
        $this->assertSame('CWE-1321', $falha['finding']['evidence']['reference']);

        // Marcador ausente na resposta de controle → protegido.
        $this->assertSame('protegido', ApiOracles::prototypePollutionAssess('/api/config', $marker, '{"theme":"dark"}')['verdict']);
        // Marcador vazio nunca prova.
        $this->assertSame('nao_testado', ApiOracles::prototypePollutionAssess('/api/config', '', '{"x":1}')['verdict']);
    }

    public function test_graphql_batching_confirms_alias_amplification_in_one_request(): void
    {
        // 50 aliases num request só, todos executaram → amplificação (fura rate-limit).
        $falha = ApiOracles::graphqlBatchingAssess('/graphql', 50, 50);
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('medium', $falha['finding']['severity']);
        $this->assertSame('OWASP API4:2023 · CWE-770', $falha['finding']['evidence']['reference']);

        // Servidor executou só 1 (limitou aliases) → protegido.
        $this->assertSame('protegido', ApiOracles::graphqlBatchingAssess('/graphql', 50, 1)['verdict']);
        // Dois aliases e dois executados já conta como amplificação.
        $this->assertSame('falha', ApiOracles::graphqlBatchingAssess('/graphql', 2, 2)['verdict']);
        // Nada executou (erro/bloqueio) → não testado.
        $this->assertSame('nao_testado', ApiOracles::graphqlBatchingAssess('/graphql', 50, 0)['verdict']);
    }

    public function test_unauthorized_write_confirms_a_state_change_without_a_session(): void
    {
        // DELETE anônimo aceito (2xx) = escrita sem autenticação provada.
        foreach ([200, 201, 202, 204] as $status) {
            $falha = ApiOracles::unauthorizedWriteAssess('/api/reservas/9', 'DELETE', $status);
            $this->assertSame('falha', $falha['verdict'], (string) $status);
            $this->assertSame('high', $falha['finding']['severity']);
            $this->assertSame('OWASP API5:2023 · CWE-285', $falha['finding']['evidence']['reference']);
            $this->assertSame('DELETE', $falha['finding']['evidence']['method']);
        }
        // Servidor exige sessão/permissão ou nega o método → protegido.
        foreach ([401, 403, 405] as $status) {
            $this->assertSame('protegido', ApiOracles::unauthorizedWriteAssess('/api/reservas/9', 'DELETE', $status)['verdict']);
        }
        // Rota inexistente / erro / sem resposta → não testado (sem falso-positivo).
        foreach ([0, 404, 500] as $status) {
            $this->assertSame('nao_testado', ApiOracles::unauthorizedWriteAssess('/api/reservas/9', 'PUT', $status)['verdict']);
        }
        // GET nunca é "escrita".
        $this->assertSame('nao_testado', ApiOracles::unauthorizedWriteAssess('/api/reservas/9', 'GET', 200)['verdict']);
    }

    public function test_race_condition_confirms_a_one_time_action_running_twice(): void
    {
        // Ação de uso único que respondeu 2xx em 3 de 5 requisições paralelas = TOCTOU.
        $falha = ApiOracles::raceAssess('/api/resgatar', 3);
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('high', $falha['finding']['severity']);
        $this->assertSame('CWE-362', $falha['finding']['evidence']['reference']);

        // Só uma venceu → atômico, protegido.
        $this->assertSame('protegido', ApiOracles::raceAssess('/api/resgatar', 1)['verdict']);
        // Nenhuma passou (bloqueio/erro) → não testado.
        $this->assertSame('nao_testado', ApiOracles::raceAssess('/api/resgatar', 0)['verdict']);
    }

    public function test_xxe_confirms_only_when_the_parser_calls_the_out_of_band_collector(): void
    {
        // Entidade externa fez o servidor chamar o coletor OOB (hit registrado) = XXE provada.
        $falha = ApiOracles::xxeAssess('/api/importar', 1);
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('high', $falha['finding']['severity']);
        $this->assertSame('OWASP A05:2021 · CWE-611', $falha['finding']['evidence']['reference']);
        $this->assertSame('/api/importar', $falha['finding']['evidence']['path']);

        // Nenhum callback → não testado (ausência de OOB não prova proteção, só não confirma).
        $this->assertSame('nao_testado', ApiOracles::xxeAssess('/api/importar', 0)['verdict']);
    }

    public function test_cloud_metadata_ssrf_confirms_only_when_instance_credentials_surface(): void
    {
        // SSRF que alcançou o IMDS da AWS e trouxe credenciais temporárias = crítico.
        $imds = '{"Code":"Success","AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"abc/def","Token":"x"}';
        $falha = ApiOracles::cloudMetadataAssess('/servicos/integrador', $imds);
        $this->assertSame('falha', $falha['verdict']);
        $this->assertSame('critical', $falha['finding']['severity']);
        $this->assertSame('OWASP A10:2021 · CWE-918', $falha['finding']['evidence']['reference']);

        // Resposta de token do GCP (corpo real, não a URL) também conta.
        $this->assertSame('falha', ApiOracles::cloudMetadataAssess('/x', '{"access_token":"ya29.abc","expires_in":3599,"token_type":"Bearer"}')['verdict']);
        // Resposta comum da aplicação nunca vira falso-positivo.
        $this->assertSame('nao_testado', ApiOracles::cloudMetadataAssess('/x', '{"ok":true,"itens":[{"id":1}]}')['verdict']);
        // Eco da URL injetada (iam/security-credentials/, computeMetadata/v1) NÃO pode disparar — era o falso-positivo da revisão.
        $this->assertSame('nao_testado', ApiOracles::cloudMetadataAssess('/x', 'destino invalido: http://169.254.169.254/latest/meta-data/iam/security-credentials/')['verdict']);
        $this->assertSame('nao_testado', ApiOracles::cloudMetadataAssess('/x', 'erro ao buscar http://metadata.google.internal/computeMetadata/v1/')['verdict']);
    }

    public function test_graphql_batching_marker_and_alias_payload_helpers(): void
    {
        $query = ApiOracles::aliasFlood('login', '(input:{email:"a@a",password:"x"})', 30);
        $this->assertSame(30, substr_count($query, 'egideAlias'));
        $this->assertStringContainsString('egideAlias0: login', $query);
        $this->assertStringContainsString('egideAlias29: login', $query);
    }
}
