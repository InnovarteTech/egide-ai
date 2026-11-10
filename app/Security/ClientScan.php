<?php

namespace App\Security;

final class ClientScan
{
    private const SINKS = [
        'dangerouslySetInnerHTML' => 'dangerouslySetInnerHTML',
        'innerHTML' => '.innerHTML',
        'outerHTML' => '.outerHTML',
        'insertAdjacentHTML' => 'insertAdjacentHTML',
        'document.write' => 'document.write',
        'eval' => 'eval(',
        'Function' => 'new Function(',
        'setAttribute' => '.setAttribute(',
        'location.assign' => 'location.assign(',
    ];

    private const SOURCES = [
        'location.hash', 'location.search', 'location.href', 'document.URL', 'document.referrer',
        'URLSearchParams', 'postMessage', 'localStorage', 'sessionStorage', '.getItem(',
        'useSearchParams', 'useParams', 'query.', 'params.', 'props.match',
    ];

    private const QUERY_SOURCES = ['location.search', 'location.href', 'document.URL', 'URLSearchParams', 'searchParams', 'useSearchParams', 'query.'];

    public static function readsQuery(string $js): bool
    {
        foreach (self::QUERY_SOURCES as $source) {
            if (str_contains($js, $source)) {
                return true;
            }
        }

        return false;
    }

    public static function sinks(string $js): array
    {
        $found = [];
        foreach (self::SINKS as $name => $needle) {
            $offset = 0;
            while (($pos = strpos($js, $needle, $offset)) !== false) {
                $window = substr($js, max(0, $pos - 160), 320);
                $source = false;
                foreach (self::SOURCES as $src) {
                    if (str_contains($window, $src)) {
                        $source = true;
                        break;
                    }
                }
                $found[] = ['sink' => $name, 'source' => $source, 'snippet' => trim(substr($js, max(0, $pos - 60), 160))];
                $offset = $pos + strlen($needle);
                if (count($found) >= 40) {
                    return $found;
                }
            }
        }

        return $found;
    }
}
