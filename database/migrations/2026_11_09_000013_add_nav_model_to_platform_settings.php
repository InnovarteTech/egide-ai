<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('platform_settings', function (Blueprint $table): void {
            $table->string('ai_nav_model')->nullable()->after('ai_model');
        });
    }

    public function down(): void
    {
        Schema::table('platform_settings', fn (Blueprint $table) => $table->dropColumn('ai_nav_model'));
    }
};
