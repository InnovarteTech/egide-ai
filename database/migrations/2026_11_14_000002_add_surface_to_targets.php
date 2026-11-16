<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('targets', function (Blueprint $table): void {
            $table->json('surface')->nullable();
            $table->json('surface_meta')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('targets', fn (Blueprint $table) => $table->dropColumn(['surface', 'surface_meta']));
    }
};
