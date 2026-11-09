<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('monitors', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('key_hash', 64)->unique();
            $table->string('key_prefix', 16);
            $table->text('webhook_url')->nullable();
            $table->timestamp('last_event_at')->nullable();
            $table->timestamps();
        });

        Schema::create('monitor_events', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('monitor_id')->constrained()->cascadeOnDelete();
            $table->string('type', 24);
            $table->string('ip', 45);
            $table->string('subject', 64)->nullable();
            $table->string('path', 255)->nullable();
            $table->unsignedSmallInteger('status')->nullable();
            $table->timestamp('occurred_at');
            $table->index(['monitor_id', 'occurred_at']);
            $table->index(['monitor_id', 'ip', 'occurred_at']);
            $table->index(['monitor_id', 'subject', 'occurred_at']);
        });

        Schema::create('alerts', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('monitor_id')->constrained()->cascadeOnDelete();
            $table->string('rule', 32);
            $table->string('severity', 12);
            $table->string('title');
            $table->text('detail');
            $table->string('ip', 45)->nullable();
            $table->string('subject', 64)->nullable();
            $table->unsignedInteger('count')->default(1);
            $table->string('fingerprint', 64);
            $table->string('status', 12)->default('open');
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamp('notified_at')->nullable();
            $table->timestamps();
            $table->unique(['monitor_id', 'fingerprint']);
            $table->index(['monitor_id', 'status', 'last_seen_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('alerts');
        Schema::dropIfExists('monitor_events');
        Schema::dropIfExists('monitors');
    }
};
