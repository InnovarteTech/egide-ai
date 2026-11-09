<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('scans', function (Blueprint $table): void {
            $table->json('summary')->nullable()->after('result');
        });
    }

    public function down(): void
    {
        Schema::table('scans', function (Blueprint $table): void {
            $table->dropColumn('summary');
        });
    }
};
