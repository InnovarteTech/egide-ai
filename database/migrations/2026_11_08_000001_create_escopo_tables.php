<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('workspaces', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->unique()->constrained()->cascadeOnDelete();
            $table->string('name')->default('Meu workspace');
            $table->string('accent', 7)->default('#6435ea');
            $table->string('provider')->default('lab');
            $table->string('model')->nullable();
            $table->text('api_key')->nullable();
            $table->timestamps();
        });

        Schema::create('targets', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('origin', 255);
            $table->string('entry_path', 255)->default('/');
            $table->string('verification_token', 64);
            $table->timestamp('verified_at')->nullable();
            $table->json('rules');
            $table->json('denied');
            $table->text('credentials')->nullable();
            $table->timestamps();
            $table->unique(['user_id', 'origin']);
        });

        Schema::create('scans', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->foreignId('target_id')->nullable()->constrained()->nullOnDelete();
            $table->string('name');
            $table->string('mode');
            $table->string('status')->default('queued');
            $table->string('provider')->default('lab');
            $table->string('model')->nullable();
            $table->json('scope');
            $table->text('engine_key')->nullable();
            $table->text('credentials')->nullable();
            $table->unsignedSmallInteger('budget')->default(80);
            $table->unsignedSmallInteger('request_count')->default(0);
            $table->unsignedSmallInteger('blocked_count')->default(0);
            $table->unsignedSmallInteger('endpoint_count')->default(0);
            $table->string('phase')->default('Fila');
            $table->string('result')->nullable();
            $table->text('error')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamp('stop_requested_at')->nullable();
            $table->timestamps();
            $table->index(['user_id', 'created_at']);
        });

        Schema::create('scan_events', function (Blueprint $table): void {
            $table->id();
            $table->foreignUuid('scan_id')->constrained()->cascadeOnDelete();
            $table->string('type');
            $table->string('title');
            $table->text('detail')->nullable();
            $table->json('data')->nullable();
            $table->timestamp('created_at');
            $table->index(['scan_id', 'id']);
        });

        Schema::create('findings', function (Blueprint $table): void {
            $table->id();
            $table->foreignUuid('scan_id')->constrained()->cascadeOnDelete();
            $table->string('title');
            $table->string('severity');
            $table->string('category');
            $table->json('evidence');
            $table->text('remediation');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('findings');
        Schema::dropIfExists('scan_events');
        Schema::dropIfExists('scans');
        Schema::dropIfExists('targets');
        Schema::dropIfExists('workspaces');
    }
};
