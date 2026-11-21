<?php

namespace Tests\Unit;

use App\Security\Hunter;
use App\Security\TechniqueCards;
use PHPUnit\Framework\TestCase;

class TechniqueCardsTest extends TestCase
{
    public function test_every_card_maps_to_a_technique_the_hunter_can_prove(): void
    {
        foreach (TechniqueCards::techniques() as $technique) {
            $this->assertContains($technique, Hunter::TECHNIQUES, "O card {$technique} não tem técnica com oráculo.");
        }
        foreach (TechniqueCards::all() as $technique => $card) {
            $this->assertNotEmpty($card['sinais'], "O card {$technique} não tem sinais.");
            $this->assertNotEmpty($card['dicas'], "O card {$technique} não tem dicas.");
            foreach ($card['dicas'] as $dica) {
                $this->assertIsString($dica);
                $this->assertNotSame('', trim($dica));
            }
        }
    }

    public function test_relevant_respects_the_limit(): void
    {
        $this->assertCount(2, TechniqueCards::relevant(['qualquer' => 'coisa'], 2));
        $this->assertCount(1, TechniqueCards::relevant([], 1));
        $this->assertCount(1, TechniqueCards::relevant([], 0));
    }

    public function test_relevant_ranks_the_fingerprinted_technique_first(): void
    {
        $sql = TechniqueCards::relevant([
            'experimentos_recentes' => [['trecho' => "You have an error in your SQL syntax near '1'' at MySQL"]],
        ], 3);
        $this->assertSame('sqli_error', $sql[0]['tecnica']);

        $graphql = TechniqueCards::relevant([
            'inventario' => [['method' => 'POST', 'path' => '/graphql']],
        ], 4);
        $this->assertContains('graphql', array_column($graphql, 'tecnica'));
    }

    public function test_relevant_returns_core_defaults_when_nothing_matches(): void
    {
        $result = TechniqueCards::relevant(['nada' => 'zzz-sem-sinal'], 3);
        $this->assertCount(3, $result);
        foreach ($result as $card) {
            $this->assertContains($card['tecnica'], Hunter::TECHNIQUES);
            $this->assertNotEmpty($card['dicas']);
        }
    }
}
