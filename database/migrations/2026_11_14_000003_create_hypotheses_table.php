<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('hypotheses', function (Blueprint $table): void {
            $table->id();
            $table->foreignUuid('scan_id')->constrained()->cascadeOnDelete();
            $table->foreignId('target_id')->nullable()->constrained()->nullOnDelete();
            $table->string('class');
            $table->string('method', 16);
            $table->string('path', 2048);
            $table->string('point')->nullable();
            $table->string('key')->nullable();
            $table->string('actor')->nullable();
            $table->string('oracle');
            $table->string('action_class');
            $table->text('expected')->nullable();
            $table->text('rationale')->nullable();
            $table->string('angle')->nullable();
            $table->string('status')->default('pendente');
            $table->text('reason')->nullable();
            $table->integer('attempts')->default(0);
            $table->unsignedBigInteger('parent_id')->nullable();
            $table->integer('cost_requests')->default(0);
            $table->timestamps();
            $table->index('scan_id');
            $table->index('status');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('hypotheses');
    }
};
