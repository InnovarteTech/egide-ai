<?php

namespace Database\Seeders;

use App\Models\User;
use App\Models\Workspace;
use Illuminate\Database\Seeder;
use Illuminate\Support\Str;

class DatabaseSeeder extends Seeder
{
    public function run(): void
    {
        $email = env('EGIDE_ADMIN_EMAIL', 'admin@egide.test');
        $password = env('EGIDE_ADMIN_PASSWORD') ?: Str::password(24);
        $user = User::firstOrCreate(
            ['email' => $email],
            ['name' => env('EGIDE_ADMIN_NAME', 'Administrador'), 'password' => $password],
        );
        if (! $user->wasRecentlyCreated && ! $user->is_admin) {
            $this->command?->error("A conta {$email} já existia sem acesso de administrador e não foi promovida. Use outro EGIDE_ADMIN_EMAIL.");

            return;
        }
        $user->forceFill(['is_admin' => true])->save();
        Workspace::firstOrCreate(['user_id' => $user->id], ['name' => env('EGIDE_WORKSPACE_NAME', 'Meu workspace')]);

        if ($user->wasRecentlyCreated && ! env('EGIDE_ADMIN_PASSWORD')) {
            $this->command?->warn("Administrador criado: {$email} · senha gerada: {$password}");
        }
    }
}
