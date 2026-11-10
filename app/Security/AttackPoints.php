<?php

namespace App\Security;

final class AttackPoints
{
    public const INJECTED = ['xss', 'sqli_time', 'sqli_error', 'sqli_bool', 'nosql', 'ssrf', 'open_redirect', 'traversal', 'graphql'];

    public const CLASSES = [...self::INJECTED, 'idor', 'rate', 'jwt'];

    public static function baseline(array $endpoint): array
    {
        $points = [];
        $path = $endpoint['path'] ?? '/';
        if (preg_match('~/(\{id\}|\d+)(?=/|$)~', $path)) {
            $points[] = ['class' => 'idor', 'point' => 'path', 'key' => 'id'];
        }
        foreach ($endpoint['params'] ?? [] as $param) {
            if (preg_match('~url|uri|link|dest|callback|webhook|redirect|next|feed|proxy~i', (string) $param)) {
                $points[] = ['class' => 'ssrf', 'point' => 'query', 'key' => $param];
            }
            if (preg_match('~^(?:r|u|to)$|redirect|return|next|url|goto|continue|dest|target|forward|redir|retorno|voltar|callback~i', (string) $param)) {
                $points[] = ['class' => 'open_redirect', 'point' => 'query', 'key' => $param];
            }
            if (preg_match('~file|path|doc|download|anexo|attach|img|image|template|lang|page|include|arquivo~i', (string) $param)) {
                $points[] = ['class' => 'traversal', 'point' => 'query', 'key' => $param];
            }
            foreach (['xss', 'sqli_time', 'sqli_error', 'nosql', 'sqli_bool'] as $class) {
                $points[] = ['class' => $class, 'point' => 'query', 'key' => $param];
            }
        }
        foreach ($endpoint['body'] ?? [] as $field) {
            $points[] = ['class' => 'xss', 'point' => 'body', 'key' => $field];
            $points[] = ['class' => 'sqli_time', 'point' => 'body', 'key' => $field];
            $points[] = ['class' => 'sqli_error', 'point' => 'body', 'key' => $field];
        }
        if (preg_match('~graphql~i', $path)) {
            $points[] = ['class' => 'graphql', 'point' => 'body', 'key' => 'query'];
        }
        if (preg_match('~/(auth|login|entrar|session|token|oauth)~i', $path)) {
            $points[] = ['class' => 'rate', 'point' => 'path', 'key' => null];
            $points[] = ['class' => 'jwt', 'point' => 'path', 'key' => null];
        }

        return $points;
    }

    public static function merge(array $baseline, array $ai): array
    {
        $seen = [];
        $out = [];
        foreach ([...$baseline, ...$ai] as $point) {
            if (! isset($point['class'], $point['point'])) {
                continue;
            }
            $key = $point['key'] ?? null;
            $signature = $point['class'].'|'.$point['point'].'|'.($key ?? '');
            if (isset($seen[$signature])) {
                continue;
            }
            $seen[$signature] = true;
            $out[] = ['class' => $point['class'], 'point' => $point['point'], 'key' => $key];
        }

        return $out;
    }
}
