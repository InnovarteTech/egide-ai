#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor_root="$project_root/.agents/vendor/superpowers"
skills_root="$project_root/.agents/skills"
version='v7.0.2'

if [[ ! -d "$vendor_root" ]]; then
    mkdir -p "$(dirname "$vendor_root")"
    git clone --depth 1 --branch "$version" https://github.com/obra/superpowers.git "$vendor_root"
fi

if [[ ! -d "$vendor_root/skills" ]]; then
    echo "Skills não encontradas em $vendor_root/skills" >&2
    exit 1
fi
if [[ "$(git -C "$vendor_root" describe --tags --exact-match)" != "$version" ]]; then
    echo "A cópia local precisa estar no tag $version." >&2
    exit 1
fi

mkdir -p "$skills_root"
for skill in "$vendor_root"/skills/*; do
    [[ -d "$skill" ]] || continue
    name="$(basename "$skill")"
    link="$skills_root/$name"
    if [[ ! -e "$link" && ! -L "$link" ]]; then
        ln -s "../vendor/superpowers/skills/$name" "$link"
    fi
    if [[ ! -L "$link" || "$(readlink "$link")" != "../vendor/superpowers/skills/$name" ]]; then
        echo "O caminho $link não aponta para a cópia local esperada." >&2
        exit 1
    fi
    if [[ ! -f "$link/SKILL.md" ]]; then
        echo "Skill indisponível em $link" >&2
        exit 1
    fi
done

echo "Superpowers $version disponível somente em $project_root. Abra uma nova sessão do Codex."
