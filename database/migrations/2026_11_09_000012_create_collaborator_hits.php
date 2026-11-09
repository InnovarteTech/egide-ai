<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('collaborator_hits', function (Blueprint $table) {
            $table->id();
            $table->string('token', 64)->index();
            $table->string('method', 10)->default('GET');
            $table->string('source_ip', 45)->nullable();
            $table->string('path', 512)->nullable();
            $table->string('user_agent', 255)->nullable();
            $table->text('body_excerpt')->nullable();
            $table->timestamp('received_at')->useCurrent();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('collaborator_hits');
    }
};
