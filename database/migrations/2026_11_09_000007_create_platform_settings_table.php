<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('platform_settings', function (Blueprint $table): void {
            $table->id();
            $table->string('ai_provider')->default('lab');
            $table->string('ai_model')->nullable();
            $table->text('ai_key')->nullable();
            $table->unsignedSmallInteger('ai_daily_limit')->default(20);
            $table->timestamps();
        });
        DB::table('platform_settings')->insert(['id' => 1, 'ai_provider' => 'lab', 'ai_daily_limit' => 20, 'created_at' => now(), 'updated_at' => now()]);
    }

    public function down(): void
    {
        Schema::dropIfExists('platform_settings');
    }
};
