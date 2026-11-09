<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('targets', function (Blueprint $table): void {
            $table->string('schedule', 12)->default('off');
            $table->timestamp('next_run_at')->nullable();
        });
        Schema::table('scans', function (Blueprint $table): void {
            $table->string('trigger', 12)->default('manual');
            $table->boolean('regression')->default(false);
        });
        Schema::table('workspaces', function (Blueprint $table): void {
            $table->text('webhook_url')->nullable();
        });
        Schema::create('api_tokens', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('token_hash', 64)->unique();
            $table->string('prefix', 16);
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('api_tokens');
        Schema::table('workspaces', fn (Blueprint $table) => $table->dropColumn('webhook_url'));
        Schema::table('scans', fn (Blueprint $table) => $table->dropColumn(['trigger', 'regression']));
        Schema::table('targets', fn (Blueprint $table) => $table->dropColumn(['schedule', 'next_run_at']));
    }
};
